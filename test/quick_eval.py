# quick_eval.py
import json, numpy as np
from datasets import load_dataset
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_curve, classification_report, average_precision_score
from scorer import post_rules  # 直接复用你现有规则

ds = load_dataset("tiangler/cybersecurity_alarm_analysis")
texts = [json.dumps(x, ensure_ascii=False) for x in ds['train']['input']]
labels = ds['train']['output']

X_tr, X_te, y_tr, y_te, _, raw_te = train_test_split(
    texts, labels, ds['train']['input'],
    test_size=0.2, stratify=labels, random_state=42
)


vec = TfidfVectorizer(max_features=8000)
Xtr = vec.fit_transform(X_tr); Xte = vec.transform(X_te)
clf = LogisticRegression(max_iter=2000, class_weight='balanced', n_jobs=-1).fit(Xtr, y_tr)

pos = '攻击'; pos_idx = list(clf.classes_).index(pos)
p = clf.predict_proba(Xte)[:, pos_idx]
yt = (np.array(y_te)==pos).astype(int)

def pick_by_f1(scores):
    prec, rec, ths = precision_recall_curve(yt, scores)
    F1 = 2*prec[:-1]*rec[:-1]/(prec[:-1]+rec[:-1]+1e-12)
    i = np.nanargmax(F1)
    return ths[i], prec[i], rec[i], F1[i]

# LR 原始
th0, P0, R0, F0 = pick_by_f1(p)

# LR + 规则
def ensure_dict(a):
    if isinstance(a, str):
        try:
            return json.loads(a)
        except Exception:
            return {}
    return a or {}

p_rule = np.array([post_rules(ensure_dict(a), s)[0] for a, s in zip(raw_te, p)], dtype=float)

th1, P1, R1, F1 = pick_by_f1(p_rule)

def ap(s): 
    from sklearn.metrics import average_precision_score
    return average_precision_score(yt, s)

print(f"[LR]        PR-AUC={ap(p):.4f}  F1*={F0:.3f} @th={th0:.3f}  P={P0:.3f} R={R0:.3f}")
print(f"[LR+RULES]  PR-AUC={ap(p_rule):.4f}  F1*={F1:.3f} @th={th1:.3f}  P={P1:.3f} R={R1:.3f}")
