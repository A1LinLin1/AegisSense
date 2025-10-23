# offline_calibrate_threshold.py
import json, math, joblib, numpy as np
from datasets import load_dataset
from sklearn.metrics import precision_recall_curve, average_precision_score

POS = '攻击'

def to_logit(p: float) -> float:
    p = min(max(float(p), 1e-6), 1-1e-6)
    return math.log(p/(1-p))

# 和 scorer.py 同步：把多字段拼成文本
def maybe_decode(v):
    if v is None: return ''
    if isinstance(v, dict):
        parts=[]
        for k,val in v.items():
            s = val if isinstance(val,str) else json.dumps(val, ensure_ascii=False)
            parts.append(f"{k}:{s}")
        return " ".join(parts)
    if isinstance(v, str): return v
    return json.dumps(v, ensure_ascii=False)

def build_text_feature(a: dict) -> str:
    g=a.get
    fields=[
        g('vuln_type',''), g('attack_type',''), g('vuln_name',''), g('rule_desc',''),
        g('uri','') or g('url_path','') or g('h_url',''),
        f"rsp_status:{g('rsp_status','')}",
        f"h_method:{g('h_method','')}",
        f"confidence:{g('confidence','')}",
        f"hazard_rating:{g('hazard_rating','')}",
        f"user-agent:{g('user-agent','') or g('User-Agent','')}",
        f"rsp_body:{maybe_decode(g('rsp_body'))[:500]}",
        f"req_header:{maybe_decode(g('req_header'))[:500]}",
        f"req_body:{maybe_decode(g('req_body'))[:500]}",
        f"payload:{maybe_decode(g('payload'))[:800]}",
    ]
    return " ".join([x for x in fields if x])

def rule_flags(a: dict):
    rb = (str(a.get('rsp_body','')) or '').lower()
    ua = (str(a.get('user-agent','') or a.get('User-Agent','')) or '').lower()
    conf = str(a.get('confidence','')).lower()
    hazard = str(a.get('hazard_rating','')).lower()
    f_resp = int(any(k in rb for k in ['非法路径','仅提供public','未授权','access denied','forbidden']))
    f_ua   = int(any(k in ua for k in ['ivre-masscan','sqlmap','go-http-client/1.1','curl/','nmap']))
    f_low  = int(any(k in conf for k in ['低','中','low','medium']) and any(k in hazard for k in ['低危','low']))
    return np.array([f_resp, f_ua, f_low], dtype=np.float32)

def choose_threshold(y_true, score, recall_floor=0.99):
    prec, rec, th = precision_recall_curve(y_true, score)
    ap = average_precision_score(y_true, score)
    F1 = 2*prec[:-1]*rec[:-1]/(prec[:-1]+rec[:-1]+1e-12)
    i_f1 = int(np.nanargmax(F1))
    th_f1, Pf1, Rf1, Ff1 = float(th[i_f1]), float(prec[i_f1]), float(rec[i_f1]), float(F1[i_f1])
    mask = rec[:-1] >= recall_floor
    if np.any(mask):
        idx = np.where(mask)[0][np.argmax(prec[:-1][mask])]
        th_rec, P99, R99 = float(th[idx]), float(prec[idx]), float(rec[idx])
        mode = "recall_target"
    else:
        th_rec, P99, R99, mode = th_f1, Pf1, Rf1, "fallback_f1"
    return ap, (th_f1,Pf1,Rf1,Ff1), (th_rec,P99,R99,mode)

def main(N=2000, recall_floor=0.99):
    # 加载模型
    vec = joblib.load('tfidf_vec.pkl')
    clf = joblib.load('logreg_model.pkl')
    try:
        fuser = joblib.load('rule_fuser.pkl')
    except Exception:
        fuser = None
    use_logit = False
    try:
        meta = json.load(open('fuser_metrics.json','r',encoding='utf-8'))
        use_logit = bool(meta.get('args',{}).get('use_logit', False))
    except Exception:
        pass

    # 数据
    ds = load_dataset("tiangler/cybersecurity_alarm_analysis")
    Xraw = ds['train']['input'][:N]
    y = np.array(ds['train']['output'][:N])
    y_true = (y==POS).astype(int)

    # 打分
    pos_idx = list(clf.classes_).index(POS)
    scores=[]
    for s in Xraw:
        a = s if isinstance(s, dict) else (json.loads(s) if isinstance(s,str) else {})
        text = build_text_feature(a)
        x = vec.transform([text])
        base_prob = float(clf.predict_proba(x)[:,pos_idx][0])
        if fuser is not None:
            feat0 = to_logit(base_prob) if use_logit else base_prob
            feats = np.array([[feat0, *rule_flags(a)]], dtype=np.float32)
            p = float(fuser.predict_proba(feats)[:,1][0])
        else:
            p = base_prob
        scores.append(p)
    scores = np.array(scores, dtype=float)

    ap, (th_f1,Pf1,Rf1,Ff1), (th_rec,P99,R99,mode) = choose_threshold(y_true, scores, recall_floor)
    print(f"[OFFLINE] PR-AUC={ap:.4f}")
    print(f"[OFFLINE/F1*] th={th_f1:.3f} P={Pf1:.3f} R={Rf1:.3f} F1={Ff1:.3f}")
    print(f"[OFFLINE@R>={recall_floor:.2f}] th={th_rec:.3f} P={P99:.3f} R={R99:.3f} mode={mode}")

    # 写回线上阈值
    with open('threshold_fuse.txt','w',encoding='utf-8') as f:
        f.write(str(th_rec))
    print("Wrote threshold_fuse.txt =", th_rec)

if __name__ == "__main__":
    main()
