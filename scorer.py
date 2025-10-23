# scorer.py
# -*- coding: utf-8 -*-
import os, json, re, base64, html, yaml, math
from urllib.parse import unquote
from datetime import datetime
from typing import Dict, Any, Tuple, List
import numpy as np
import joblib
from collections import OrderedDict

# ------------ 路径 & 文件名统一 ------------
_HERE = os.path.dirname(__file__)

# 与 bench.py 保持一致的模型/向量器文件名
_VEC_PATH = os.path.join(_HERE, 'tfidf_vec.pkl')
_CLF_PATH = os.path.join(_HERE, 'logreg_model.pkl')

# 可选融合器与元信息
_FUSER_PATH = os.path.join(_HERE, 'rule_fuser.pkl')
_FUSER_META_PATH = os.path.join(_HERE, 'fuser_metrics.json')

# 阈值文件（calibrate 写 threshold_fuse.txt，回退到 threshold.txt）
_TH_FUSE_PATH = os.path.join(_HERE, 'threshold_fuse.txt')
_TH_BASE_PATH = os.path.join(_HERE, 'threshold.txt')

# 规则配置（可选）
_RULES_YAML = os.path.join(_HERE, 'rules.yaml')

# ------------ 加载模型 ------------
_VEC = joblib.load(_VEC_PATH)
_CLF = joblib.load(_CLF_PATH)
_POS_LABEL = '攻击'
_NEG_LABEL = '误报'
_POS_IDX = list(_CLF.classes_).index(_POS_LABEL)

def _load_float(path, default=None):
    try:
        return float(open(path, 'r', encoding='utf-8').read().strip())
    except Exception:
        return default

# 融合器（可选）
try:
    _FUSER = joblib.load(_FUSER_PATH)
except Exception:
    _FUSER = None

# 是否在融合器使用 logit 特征
_USE_LOGIT = False
try:
    _FUSER_META = json.load(open(_FUSER_META_PATH, 'r', encoding='utf-8'))
    _USE_LOGIT = bool(_FUSER_META.get('args', {}).get('use_logit', False))
except Exception:
    _USE_LOGIT = False

def _read_best_th() -> float:
    """优先读融合阈值，其次基础阈值；无则 0.95"""
    th_fuse = _load_float(_TH_FUSE_PATH, None)
    if th_fuse is not None:
        return th_fuse
    return _load_float(_TH_BASE_PATH, 0.95)

def _to_logit(p: float) -> float:
    p = min(max(float(p), 1e-6), 1-1e-6)
    return math.log(p/(1-p))

# ------------ 规则常量（可按需增减） ------------
RSP_WHITELIST_KWS = ['非法路径', '仅提供public', '未授权', 'access denied', 'forbidden']
SCANNER_UA_SIGS   = ['ivre-masscan', 'sqlmap', 'go-http-client/1.1', 'curl/', 'nmap']
LOW_CONF_VALUES   = ['低', '中', 'low', 'medium']
LOW_HAZARD_VALUES = ['低危', 'low']

# ------------ 融合权重（可按需调节） ------------
ALPHA_LOG = 1.0   # 日志/文本模型权重
BETA_FLOW = 0.6   # 流量权重
GAMMA_TOPO = 0.8  # 拓扑权重

# ------------ 导入 rules.yaml（可选） ------------
CONF = {}
if os.path.exists(_RULES_YAML):
    try:
        CONF = yaml.safe_load(open(_RULES_YAML, "r", encoding="utf-8"))
    except Exception:
        CONF = {}

# ------------ 工具函数 ------------
def _norm01(x, lo, hi):
    if hi <= lo: return 0.0
    v = (float(x) - lo) / (hi - lo)
    return max(0.0, min(1.0, v))

# 去重缓存（key -> last_seen_epoch_sec），限制大小防止内存增长
_LAST_SEEN: "OrderedDict[Tuple[str,str,str], int]" = OrderedDict()
_MAX_KEYS = 100_000
DEDUP_TTL_SEC = 10 * 60  # 10分钟窗口

def _touch_seen(key, t):
    _LAST_SEEN[key] = t
    _LAST_SEEN.move_to_end(key, last=True)
    if len(_LAST_SEEN) > _MAX_KEYS:
        _LAST_SEEN.popitem(last=False)

def _safe_b64(s: str) -> str:
    if not s or not isinstance(s, str): return ''
    try:
        clean = re.sub(r'[^A-Za-z0-9+/=]', '', s)
        missing = (-len(clean)) % 4
        if missing: clean += '=' * missing
        return base64.b64decode(clean, validate=False).decode('utf-8', errors='ignore')
    except Exception:
        return ''

def _maybe_decode_payload(val: Any) -> str:
    """自动解码 payload 字段（可能是base64/URL/HTML混合），统一返回可读文本"""
    if val is None: return ''
    if isinstance(val, dict):
        parts = []
        for k, v in val.items():
            text = ''
            if isinstance(v, (bytes, bytearray)):
                try: text = v.decode('utf-8', 'ignore')
                except: text = ''
            elif isinstance(v, str):
                text = _safe_b64(v) or unquote(v) or v
            else:
                text = str(v)
            parts.append(f"{k}:{text}")
        return ' '.join(parts)
    if isinstance(val, str):
        return _safe_b64(val) or unquote(val) or html.unescape(val)
    return str(val)

def _to_int_ts(v: Any) -> int:
    """从 access_time / write_date 等推断 epoch 秒"""
    if v is None: return 0
    if isinstance(v, (int, float)):
        return int(v if v < 10**12 else v/1000)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return int(datetime.strptime(str(v), fmt).timestamp())
        except Exception:
            pass
    try: return int(float(v))
    except Exception: return 0

# ------------ 特征提取 ------------
def build_text_feature(alert: Dict[str, Any]) -> str:
    """将多平台日志字段尽量统一拼成文本特征"""
    if isinstance(alert, str):
        try: alert = json.loads(alert)
        except Exception: return alert

    g = alert.get
    payload_txt = _maybe_decode_payload(g('payload'))
    fields = [
        g('vuln_type',''), g('attack_type',''), g('vuln_name',''), g('rule_desc',''),
        g('uri','') or g('url_path','') or g('h_url',''),
        f"rsp_status:{g('rsp_status','')}",
        f"h_method:{g('h_method','')}",
        f"confidence:{g('confidence','')}",
        f"hazard_rating:{g('hazard_rating','')}",
        f"hazard_level:{g('hazard_level','')}",
        f"user-agent:{g('user-agent','') or g('User-Agent','')}",
        f"rsp_body:{_maybe_decode_payload(g('rsp_body'))[:500]}",
        f"req_header:{_maybe_decode_payload(g('req_header'))[:500]}",
        f"req_body:{_maybe_decode_payload(g('req_body'))[:500]}",
        f"payload:{payload_txt[:800]}",
    ]
    return ' '.join([x for x in fields if x])

# ------------ 规则特征（给融合器用的布尔 flags）------------
def _rule_flags(alert: dict) -> np.ndarray:
    rb = (str(alert.get('rsp_body','')) or '').lower()
    ua = (str(alert.get('user-agent','') or alert.get('User-Agent','') or '')).lower()
    conf = str(alert.get('confidence','')).lower()
    hazard = str(alert.get('hazard_rating','')).lower()
    f_resp = int(any(k in rb for k in ['非法路径','仅提供public','未授权','access denied','forbidden']))
    f_ua   = int(any(k.lower() in ua for k in ['ivre-masscan','sqlmap','go-http-client/1.1','curl/','nmap']))
    f_low  = int(any(k in conf for k in ['低','中','low','medium']) and any(k in hazard for k in ['低危','low']))
    return np.array([f_resp, f_ua, f_low], dtype=np.float32)

# ------------ 规则后处理（降噪 + 去重副作用）------------
def post_rules(alert: Dict[str, Any], score: float) -> Tuple[float, List[str], str]:
    """返回(调整后的分, 命中的规则列表, 去重状态字符串)；在有融合器时不建议改分，仅用于副作用"""
    hits = []
    label = None

    # 1) 响应体白名单关键字 → 降权
    rb = str(alert.get('rsp_body',''))
    if any(kw.lower() in rb.lower() for kw in RSP_WHITELIST_KWS):
        score *= 0.85
        hits.append('rule:resp_whitelist')

    # 2) 扫描器/探测UA → 降权
    ua = str(alert.get('user-agent','') or alert.get('User-Agent',''))
    if any(sig.lower() in ua.lower() for sig in SCANNER_UA_SIGS):
        score *= 0.9
        hits.append('rule:scanner_ua')

    # 3) 低危低信度 + 低分 → 直接判误报倾向
    conf = str(alert.get('confidence','')).lower()
    hazard = str(alert.get('hazard_rating','')).lower()
    if any(x in conf for x in LOW_CONF_VALUES) and any(x in hazard for x in LOW_HAZARD_VALUES) and score < 0.80:
        score *= 0.85
        hits.append('rule:low_conf_low_hazard_drop')

    # 4) 10分钟重复抑制（同源同宿同路径）
    try:
        sip = str(alert.get('sip') or alert.get('attack_sip') or '')
        dip = str(alert.get('dip') or alert.get('alarm_sip') or '')
        upath = str(alert.get('url_path') or alert.get('uri') or '')
        t = _to_int_ts(alert.get('access_time') or alert.get('write_date'))
        key = (sip, dip, upath)
        if sip and dip and upath and t:
            last = _LAST_SEEN.get(key, 0)
            if t - last < DEDUP_TTL_SEC:
                score *= 0.6
                hits.append('rule:dedup_10min')
            _touch_seen(key, t)
    except Exception:
        pass

    return score, hits, (label or '')

# ------------ 流量与拓扑打分 ------------
def score_flow(flow: dict | None) -> float:
    if not isinstance(flow, dict): return 0.0
    syn = flow.get("syn", 0); ack = flow.get("ack", 0)
    conn_rate = flow.get("conn_rate", 0)
    uniq_dport = flow.get("uniq_dport", 0)
    bytes_out = flow.get("bytes_out", 0); bytes_in = flow.get("bytes_in", 0)
    syn_ratio = syn / max(1.0, ack)
    out_in = bytes_out / max(1.0, bytes_in)
    s_syn  = _norm01(syn_ratio, 1.5, 5.0)
    s_conn = _norm01(conn_rate, 30, 200)
    s_port = _norm01(uniq_dport, 20, 200)
    s_dir  = _norm01(out_in, 5, 200)
    return float((s_syn + s_conn + s_port + s_dir) / 4.0)

def score_topo(topo: dict | None) -> float:
    if not isinstance(topo, dict): return 0.0
    crit = topo.get("criticality", 1)  # 1~5
    exposed = 1.0 if topo.get("internet_exposed", False) else 0.0
    seg = 1.0 if topo.get("seg_cross", False) else 0.0
    patch_delay = topo.get("patch_delay_days", 0)
    s_crit  = _norm01(crit, 1, 5)
    s_patch = _norm01(patch_delay, 7, 90)
    s = 0.5*s_crit + 0.2*exposed + 0.2*seg + 0.1*s_patch
    return float(max(0.0, min(1.0, s)))

# ------------ 模型打分（统一唯一版本，支持融合器 & logit）------------
def model_score(text: str, alert_obj: dict) -> tuple[float, list[str]]:
    x = _VEC.transform([text])
    base_prob = float(_CLF.predict_proba(x)[:, _POS_IDX][0])

    # 解释性词项
    try:
        coef = _CLF.coef_[_POS_IDX]; nz = x.nonzero()[1]
        contrib = [(i, coef[i]*x[0, i]) for i in nz]
        contrib.sort(key=lambda t: t[1], reverse=True)
        names = _VEC.get_feature_names_out()
        top_terms = [names[i] for i, _ in contrib[:10]]
    except Exception:
        top_terms = []

    if _FUSER is not None:
        flags = _rule_flags(alert_obj)
        feat0 = _to_logit(base_prob) if _USE_LOGIT else base_prob
        feats = np.array([[feat0, *flags]], dtype=np.float32)
        prob = float(_FUSER.predict_proba(feats)[:, 1][0])
    else:
        prob = base_prob

    return prob, top_terms

# ------------ 主函数 ------------
def score_alert(alert: dict, flow: dict | None = None, topo: dict | None = None) -> dict:
    if isinstance(alert, str):
        try:
            alert = json.loads(alert)
        except Exception:
            alert = {}

    # 1) 文本特征 + 模型/融合器分
    text = build_text_feature(alert)
    score_model, top_terms = model_score(text, alert_obj=alert)

    # 2) 规则副作用：有融合器时不改分，仅记录规则命中与触发去重；无融合器时按旧逻辑降噪改分
    rules = []
    if _FUSER is not None:
        _, rules, _ = post_rules(alert, score_model)
        score_after_rules = score_model
    else:
        score_after_rules, rules, _ = post_rules(alert, score_model)

    # 3) 可选外部分
    s_flow = score_flow(flow)
    s_topo = score_topo(topo)

    # 4) 融合
    weights = ALPHA_LOG + (BETA_FLOW if flow else 0.0) + (GAMMA_TOPO if topo else 0.0)
    score_fused = (ALPHA_LOG*score_after_rules + BETA_FLOW*s_flow + GAMMA_TOPO*s_topo) / max(1e-9, weights)

    # 5) 动态阈值（支持校准后热生效）
    th = _read_best_th()
    label = _POS_LABEL if score_fused >= th else _NEG_LABEL

    return {
        "score_raw": round(score_model, 6),
        "score_final": round(score_fused, 6),
        "label": label,
        "threshold": th,
        "rules": rules,
        "top_terms": top_terms,
        "flow_score": round(s_flow, 6),
        "topo_score": round(s_topo, 6),
        "flags": _rule_flags(alert).tolist()
    }

def predict_alert(alert: Dict[str, Any]) -> str:
    return score_alert(alert)['label']
