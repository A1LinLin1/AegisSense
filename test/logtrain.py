# logtrain.py
import json
import numpy as np
from datasets import load_dataset
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_fscore_support, classification_report
import joblib

# ========== 1. 加载数据集 ==========
ds = load_dataset("tiangler/cybersecurity_alarm_analysis")
# 如果数据集字段名不同，请用 print(ds['train'][0]) 看字段名
# 这里假设 ds['train'] 里有 'input' 和 'output' 字段
texts = [json.dumps(x, ensure_ascii=False) for x in ds['train']['input']]
labels = ds['train']['output']

# ========== 2. 划分训练/测试集 ==========
X_train, X_test, y_train, y_test = train_test_split(
    texts, labels, test_size=0.2, stratify=labels, random_state=42
)

# ========== 3. 向量化 + 训练 ==========
vec = TfidfVectorizer(max_features=8000)
X_tr = vec.fit_transform(X_train)
X_te = vec.transform(X_test)

clf = LogisticRegression(max_iter=2000, class_weight='balanced', n_jobs=-1)
clf.fit(X_tr, y_train)

# ========== 4. 阈值扫描 ==========
pos = '攻击'
p = clf.predict_proba(X_te)[:, list(clf.classes_).index(pos)]
ths = np.linspace(0.8, 1.0, 1000)

def fbeta(p,y,th,beta=1.0):
    pred = np.where(p>=th, pos, '误报')
    pr, rc, f1, _ = precision_recall_fscore_support(
        y, pred, labels=[pos,'误报'], zero_division=0
    )
    P, R = pr[0], rc[0]
    if P+R==0: return 0, P, R
    fbeta = (1+beta**2)*P*R/(beta**2*P+R+1e-12)
    return fbeta, P, R

results = []
for t in ths:
    fbeta_val, P, R = fbeta(p, y_test, t, beta=1.0)
    results.append(((fbeta_val, P, R), t))

(best_f, bestP, bestR), best_th = max(results, key=lambda x:x[0][0])
print(f"Best threshold={best_th:.6f} | 攻击类 P={bestP:.3f}, R={bestR:.3f}, F1≈{best_f:.3f}")

pred_test = np.where(p>=best_th, pos, '误报')
print(classification_report(y_test, pred_test, digits=3))

# ========== 5. 保存模型 ==========
joblib.dump(vec, 'tfidf_vec.pkl')
joblib.dump(clf, 'logreg_model.pkl')
with open('threshold.txt','w') as f:
    f.write(str(best_th))
print("模型、向量器和阈值已保存。")

# ========== 6. 单条日志预测函数 ==========
def load_model():
    vec = joblib.load('tfidf_vec.pkl')
    clf = joblib.load('logreg_model.pkl')
    best_th = float(open('threshold.txt').read())
    return vec, clf, best_th

def predict_alert(alert_json):
    vec, clf, best_th = load_model()
    txt = json.dumps(alert_json, ensure_ascii=False)
    x_vec = vec.transform([txt])
    p = clf.predict_proba(x_vec)[:, list(clf.classes_).index('攻击')][0]
    return '攻击' if p >= best_th else '误报'
