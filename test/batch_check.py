# batch_check.py
import json, requests, sys
from datasets import load_dataset

URL = "http://127.0.0.1:8000/predict"
N = 1000  # 抽样条数，按需增大

def to_obj(x):
    if isinstance(x, dict):
        return x
    if isinstance(x, str):
        try:
            return json.loads(x)
        except Exception:
            return {}  # 兜底，避免 422
    return {}

def main():
    ds = load_dataset("tiangler/cybersecurity_alarm_analysis")
    X = ds['train']['input']
    y = ds['train']['output']

    s = requests.Session()
    tp=fp=tn=fn=0
    bad = 0

    for i, (a, label) in enumerate(zip(X[:N], y[:N]), 1):
        payload = {"alert": to_obj(a)}  # 确保是 dict
        try:
            resp = s.post(URL, json=payload, timeout=10)
        except Exception as e:
            bad += 1
            if bad <= 5: print(f"[ERR] request failed #{i}: {e}", file=sys.stderr)
            continue

        # 先检查状态码
        if resp.status_code != 200:
            bad += 1
            if bad <= 5: print(f"[ERR] status={resp.status_code} body={resp.text[:200]}", file=sys.stderr)
            continue

        # 再取 JSON
        try:
            data = resp.json()
        except Exception as e:
            bad += 1
            if bad <= 5: print(f"[ERR] json parse #{i}: {e} raw={resp.text[:200]}", file=sys.stderr)
            continue

        if 'label' not in data:
            bad += 1
            if bad <= 5: print(f"[ERR] no 'label' in resp #{i}: {data}", file=sys.stderr)
            continue

        pred = data['label']
        if label=='攻击' and pred=='攻击': tp+=1
        elif label=='攻击' and pred=='误报': fn+=1
        elif label=='误报' and pred=='攻击': fp+=1
        else: tn+=1

    print({"tp":tp, "fn":fn, "fp":fp, "tn":tn, "bad":bad})

if __name__ == "__main__":
    main()
