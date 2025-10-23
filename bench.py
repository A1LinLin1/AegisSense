# bench.py
# -*- coding: utf-8 -*-
import json, numpy as np, os
from datasets import load_dataset
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_curve, classification_report, average_precision_score, confusion_matrix
import joblib

# 1) 载入数据
ds = load_dataset("tiangler/cybersecurity_alarm_analysis")
texts = [json.dumps(x, ensure_ascii=False) for x in ds['train']['input']]
labels = ds['train']['output']

X_tr, X_te, y_tr, y_te, raw_te = train_test_split(
    texts, labels, ds['train']['input'],
    test_size=0.2, stratify=labels, random_state=42
)

# 2) TF-IDF + LR
vec = TfidfVectorizer(max_features=8000)
Xtr = vec.fit_transform(X_tr); Xte = vec.transform(X_te)
clf = LogisticRegression(max_iter=2000, class_weight='balanced').fit(Xtr, y_tr)

pos = '攻击'; pos_idx = list(clf.classes_).index(pos)
p = clf.predict_proba(Xte)[:, pos_idx]
yt = (np.array(y_te) == pos).astype(int)

def pick_f1_threshold(y_true, scores):
    prec, rec, ths = precision_recall_curve(y_true, scores)
    if len(ths) == 0:
        return float(np.median(scores)), prec, rec, ths
    F1 = 2*prec[:-1]*rec[:-1]/(prec[:-1]+rec[:-1]+1e-12)
    return float(ths[np.nanargmax(F1)]), prec, rec, ths

th_lr, prec, rec, ths = pick_f1_threshold(yt, p)
pred_lr = np.where(p >= th_lr, pos, '误报')

# 3) 可选：规则后处理（若需要与线上 post_rules 一致，可从 scorer 导入）
try:
    from scorer import post_rules
    p_rule = np.array([post_rules(a, s)[0] for a, s in zip(raw_te, p)], dtype=float)
    th_rule, prec2, rec2, ths2 = pick_f1_threshold(yt, p_rule)
    pred_rule = np.where(p_rule >= th_rule, pos, '误报')
except Exception:
    p_rule, th_rule, pred_rule = p, th_lr, pred_lr

# 4) 这里没有 flow/topo，融合等同于规则阶段
p_fuse, th_fuse, pred_fuse = p_rule, th_rule, pred_rule

def pr_auc(y_true, scores): 
    return average_precision_score(y_true, scores)

def summarize(name, y_true_lbl, scores, y_pred_lbl):
    ap = pr_auc((np.array(y_true_lbl) == pos).astype(int), scores)
    cm = confusion_matrix(np.array(y_true_lbl)==pos, np.array(y_pred_lbl)==pos)
    tn, fp, fn, tp = cm.ravel()
    print(f"\n=== {name} ===")
    print("PR-AUC:", ap)
    print(classification_report(y_true_lbl, y_pred_lbl, digits=3))
    print(f"TP={tp} FP={fp} FN={fn} TN={tn}")
    return ap

print("=== ONLY LR ===")
summarize("ONLY LR", y_te, p, pred_lr)

print("\n=== LR + RULES ===")
summarize("LR + RULES", y_te, p_rule, pred_rule)

print("\n=== LR + RULES + FUSION ===")
summarize("LR + RULES + FUSION", y_te, p_fuse, pred_fuse)

# 5) 持久化（与 scorer.py 的文件名对齐）
joblib.dump(vec, "tfidf_vec.pkl")
joblib.dump(clf, "logreg_model.pkl")
with open("threshold_fuse.txt", "w", encoding="utf-8") as f:
    f.write(str(float(th_fuse)))

print("\n[Saved] tfidf_vec.pkl, logreg_model.pkl, threshold_fuse.txt")
