# -*- coding: utf-8 -*-
"""
rule_fusion_train.py
方法二：把“规则”当作特征，与基础模型分数一起送入二层 LR 融合器学习权重。
- 训练并保存：
    tfidf_vec.pkl        （一层 TF-IDF 向量器）
    logreg_model.pkl     （一层 Logistic 回归基模）
    rule_fuser.pkl       （二层融合器）
    threshold_fuse.txt   （线上优先使用的融合阈值：R>=recall_floor 下 P 最大的阈值）
    fuser_metrics.json   （评测指标与训练参数，方便回溯）
"""

import os, json, argparse
import numpy as np
from datasets import load_dataset
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_curve, average_precision_score, classification_report
import joblib

POS_LABEL = '攻击'
NEG_LABEL = '误报'


# ----------------------------- 实用函数 -----------------------------
def to_dict(s):
    if isinstance(s, dict):
        return s
    if isinstance(s, str):
        try:
            return json.loads(s)
        except Exception:
            return {}
    return {}


def rule_flags(alert_obj):
    """
    返回 3 个布尔特征:
      f_resp: 响应体白名单/拒绝类文案
      f_ua  : 扫描器/探测 UA
      f_low : 低信度 + 低危
    """
    a = to_dict(alert_obj)
    rb = (str(a.get('rsp_body', '')) or '').lower()
    ua = (str(a.get('user-agent', '') or a.get('User-Agent', '')) or '').lower()
    conf = str(a.get('confidence', '')).lower()
    hazard = str(a.get('hazard_rating', '')).lower()

    f_resp = int(any(k in rb for k in ['非法路径', '仅提供public', '未授权', 'access denied', 'forbidden']))
    f_ua   = int(any(k in ua for k in ['ivre-masscan', 'sqlmap', 'go-http-client/1.1', 'curl/', 'nmap']))
    f_low  = int(any(k in conf for k in ['低', '中', 'low', 'medium']) and any(k in hazard for k in ['低危', 'low']))

    return np.array([f_resp, f_ua, f_low], dtype=np.float32)


def best_by_f1(y_true, score):
    prec, rec, th = precision_recall_curve(y_true, score)
    if len(th) == 0:
        return 0.5, 0.0, 0.0, 0.0
    F1 = 2 * prec[:-1] * rec[:-1] / (prec[:-1] + rec[:-1] + 1e-12)
    idx = int(np.nanargmax(F1))
    return th[idx], float(prec[idx]), float(rec[idx]), float(F1[idx])


def max_precision_at_recall(y_true, score, recall_floor=0.99):
    """
    在召回 >= recall_floor 的阈值集合中选 precision 最大的阈值。
    若没有满足的点，回退到 F1 最优阈值。
    """
    prec, rec, th = precision_recall_curve(y_true, score)
    if len(th) == 0:
        return 0.5, 0.0, 0.0, 0.0, "empty"
    mask = rec[:-1] >= recall_floor
    if not np.any(mask):
        # fallback to F1
        F1 = 2 * prec[:-1] * rec[:-1] / (prec[:-1] + rec[:-1] + 1e-12)
        idx = int(np.nanargmax(F1))
        return float(prec[idx]), float(rec[idx]), float(th[idx]), float(F1[idx]), "fallback_f1"
    idxs = np.where(mask)[0]
    # 在满足召回的集合中取 precision 最大
    best_local = int(idxs[np.argmax(prec[:-1][mask])])
    # 这里返回的 F1 是该点的 F1，便于记录
    F1 = 2 * prec[:-1] * rec[:-1] / (prec[:-1] + rec[:-1] + 1e-12)
    return float(prec[best_local]), float(rec[best_local]), float(th[best_local]), float(F1[best_local]), "recall_target"


def to_logit(p):
    """将概率映射到 logit 空间，便于二层 LR 更好利用极端置信度。"""
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p)).astype(np.float32)


# ----------------------------- 训练主流程 -----------------------------
def main(args):
    print("Loading dataset:", args.dataset)
    ds = load_dataset(args.dataset)

    texts = [json.dumps(x, ensure_ascii=False) for x in ds['train']['input']]
    labels = ds['train']['output']
    raw = ds['train']['input']  # 原始 JSON 字符串（训练规则特征）

    X_tr, X_te, y_tr, y_te, raw_tr, raw_te = train_test_split(
        texts, labels, raw, test_size=args.test_size, stratify=labels, random_state=args.seed
    )

    print("Vectorizing (TF-IDF)...")
    vec = TfidfVectorizer(max_features=args.max_features)
    Xtr = vec.fit_transform(X_tr)
    Xte = vec.transform(X_te)

    print("Training base LogisticRegression...")
    base = LogisticRegression(max_iter=args.base_max_iter, class_weight='balanced', n_jobs=None)
    base.fit(Xtr, y_tr)

    classes = list(base.classes_)
    pos_idx = classes.index(POS_LABEL)
    # 基础概率
    p_tr = base.predict_proba(Xtr)[:, pos_idx].astype(np.float32)
    p_te = base.predict_proba(Xte)[:, pos_idx].astype(np.float32)

    # 规则布尔特征
    print("Building rule flags...")
    Ftr_flags = np.vstack([rule_flags(a) for a in raw_tr]).astype(np.float32)  # (N_tr, 3)
    Fte_flags = np.vstack([rule_flags(a) for a in raw_te]).astype(np.float32)  # (N_te, 3)

    # 一层输出特征（可选用 logit）
    if args.use_logit:
        base_feat_tr = to_logit(p_tr).reshape(-1, 1)
        base_feat_te = to_logit(p_te).reshape(-1, 1)
    else:
        base_feat_tr = p_tr.reshape(-1, 1)
        base_feat_te = p_te.reshape(-1, 1)

    # 二层输入 = [基模特征, 3个规则布尔特征]
    F_tr = np.column_stack([base_feat_tr, Ftr_flags]).astype(np.float32)
    F_te = np.column_stack([base_feat_te, Fte_flags]).astype(np.float32)

    # 训练融合器
    print("Training fusion LogisticRegression...")
    y_tr_bin = (np.array(y_tr) == POS_LABEL).astype(int)
    y_te_bin = (np.array(y_te) == POS_LABEL).astype(int)

    cw_pos = float(args.pos_class_weight)
    fuser = LogisticRegression(max_iter=args.fuser_max_iter,
                               class_weight={0: 1.0, 1: cw_pos})
    fuser.fit(F_tr, y_tr_bin)

    p_fuse = fuser.predict_proba(F_te)[:, 1]

    # 评测
    ap_base = average_precision_score(y_te_bin, p_te)
    th_b, Pb, Rb, Fb = best_by_f1(y_te_bin, p_te)

    ap_fuse = average_precision_score(y_te_bin, p_fuse)
    th_f1, Pf1, Rf1, Ff1 = best_by_f1(y_te_bin, p_fuse)
    P99, R99, th_rec, F_at_rec, sel_mode = max_precision_at_recall(y_te_bin, p_fuse, recall_floor=args.recall_floor)

    print(f"[BASE] PR-AUC={ap_base:.4f} F1*={Fb:.3f} @th={th_b:.3f} P={Pb:.3f} R={Rb:.3f}")
    print(f"[FUSE/F1]  PR-AUC={ap_fuse:.4f} F1*={Ff1:.3f} @th={th_f1:.3f} P={Pf1:.3f} R={Rf1:.3f}")
    print(f"[FUSE@R>={args.recall_floor:.2f}] P={P99:.3f} R={R99:.3f} th={th_rec:.3f} mode={sel_mode}")

    # 保存模型与阈值（线上优先使用“召回优先”阈值）
    joblib.dump(vec, 'tfidf_vec.pkl')
    joblib.dump(base, 'logreg_model.pkl')
    joblib.dump(fuser, 'rule_fuser.pkl')
    with open('threshold_fuse.txt', 'w', encoding='utf-8') as f:
        f.write(str(th_rec))

    # 保存元信息便于回溯
    meta = {
        "args": vars(args),
        "base": {"pr_auc": float(ap_base), "f1": float(Fb), "th_f1": float(th_b), "P": float(Pb), "R": float(Rb)},
        "fuse_f1": {"pr_auc": float(ap_fuse), "f1": float(Ff1), "th_f1": float(th_f1), "P": float(Pf1), "R": float(Rf1)},
        "fuse_recall_pref": {
            "recall_floor": args.recall_floor,
            "P": float(P99), "R": float(R99), "th": float(th_rec), "F1_at_point": float(F_at_rec),
            "mode": sel_mode
        },
        "class_map": {"pos": POS_LABEL, "neg": NEG_LABEL},
        "feature_layout": ["base_prob_or_logit", "f_resp", "f_ua", "f_low"]
    }
    with open('fuser_metrics.json', 'w', encoding='utf-8') as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print("Saved tfidf_vec.pkl, logreg_model.pkl, rule_fuser.pkl, threshold_fuse.txt, fuser_metrics.json")
    print("Done.")


# ----------------------------- CLI -----------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train rule-fusion model (method-2).")
    parser.add_argument("--dataset", type=str, default="tiangler/cybersecurity_alarm_analysis",
                        help="HF dataset name")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)

    parser.add_argument("--max-features", type=int, default=8000,
                        help="TF-IDF max_features")
    parser.add_argument("--base-max-iter", type=int, default=2000)

    parser.add_argument("--use-logit", action="store_true", default=True,
                        help="Use logit(base_prob) as fusion feature")
    parser.add_argument("--pos-class-weight", type=float, default=2.0,
                        help="Class weight for positive (attack) in fusion LR")
    parser.add_argument("--fuser-max-iter", type=int, default=1000)

    parser.add_argument("--recall-floor", type=float, default=0.99,
                        help="Choose threshold with max Precision given Recall >= floor")

    args = parser.parse_args()
    main(args)
