# api_calibrate_threshold.py
# -*- coding: utf-8 -*-
import argparse
import os, json, requests, numpy as np
from datasets import load_dataset
from sklearn.metrics import precision_recall_curve, average_precision_score
import matplotlib.pyplot as plt

# ========== 工具函数 ==========
def to_obj(x):
    if isinstance(x, dict): return x
    if isinstance(x, str):
        try: return json.loads(x)
        except: return {}
    return {}

def draw_pr_curve(prec, rec, th, ap, selected_idx, out_png):
    plt.figure(figsize=(7, 5))
    plt.plot(rec, prec, lw=2, label=f"PR curve (AP={ap:.4f})")
    if selected_idx is not None and 0 <= selected_idx < len(th):
        px, rx = float(prec[selected_idx]), float(rec[selected_idx])
        plt.scatter([rx], [px], s=60, c='red', label=f"selected (P={px:.3f}, R={rx:.3f})")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Precision-Recall Curve (from API scores)")
    plt.grid(True, linestyle='--', alpha=0.4)
    plt.legend(loc="lower left")
    plt.tight_layout()
    plt.savefig(out_png, dpi=160)
    plt.close()

def export_pr_points(prec, rec, th, out_csv):
    m = len(th)
    with open(out_csv, "w", encoding="utf-8") as f:
        f.write("threshold,precision,recall\n")
        for i in range(m):
            f.write(f"{th[i]},{prec[i]},{rec[i]}\n")

# ========== 主逻辑 ==========
def main(args):
    URL = args.url
    N = args.n
    RECALL_FLOOR = args.recall_floor

    # 静态目录（统一写入到 static/）
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    os.makedirs(static_dir, exist_ok=True)
    out_png = os.path.join(static_dir, "pr_curve_api.png")
    out_csv = os.path.join(static_dir, "pr_points_api.csv")
    out_th = os.path.join(os.path.dirname(__file__), "threshold_fuse.txt")

    print(f"[INFO] Fetching {N} samples from API: {URL}")
    ds = load_dataset("tiangler/cybersecurity_alarm_analysis")
    X = ds['train']['input'][:N]
    y = ds['train']['output'][:N]
    y_true = (np.array(y) == '攻击').astype(int)

    s = requests.Session()
    scores = []
    for i, a in enumerate(X, 1):
        try:
            r = s.post(URL, json={"alert": to_obj(a)}, timeout=10)
            if r.status_code != 200:
                continue
            d = r.json()
            score = d.get('score_final', d.get('score_raw'))
            if score is not None:
                scores.append(float(score))
        except Exception:
            continue
    if not scores:
        raise RuntimeError("未能从 API 获取任何有效分数，请检查 /predict 是否在运行。")

    scores = np.array(scores)
    y_true = y_true[:len(scores)]
    ap = average_precision_score(y_true, scores)
    prec, rec, th = precision_recall_curve(y_true, scores)

    if len(th) == 0:
        raise RuntimeError("precision_recall_curve 返回空结果，数据可能全为同类。")

    # 计算 F1 最优
    F1 = 2*prec[:-1]*rec[:-1]/(prec[:-1]+rec[:-1]+1e-12)
    i_f1 = int(np.nanargmax(F1))
    th_f1 = float(th[i_f1]); Pf1 = float(prec[i_f1]); Rf1 = float(rec[i_f1]); Ff1 = float(F1[i_f1])

    # 召回优先模式
    mask = (rec[:-1] >= RECALL_FLOOR)
    if np.any(mask):
        cand_idx = np.where(mask)[0]
        i_rec = int(cand_idx[np.argmax(prec[:-1][mask])])
        th_rec = float(th[i_rec]); Prec_rec = float(prec[i_rec]); Rec_rec = float(rec[i_rec])
        sel_mode = "recall_target"
    else:
        th_rec, Prec_rec, Rec_rec, sel_mode = th_f1, Pf1, Rf1, "fallback_f1"
        i_rec = i_f1

    print(f"[API] PR-AUC={ap:.4f}")
    print(f"[API/F1*] th={th_f1:.3f} P={Pf1:.3f} R={Rf1:.3f} F1={Ff1:.3f}")
    print(f"[API@R>={RECALL_FLOOR:.2f}] th={th_rec:.3f} P={Prec_rec:.3f} R={Rec_rec:.3f} mode={sel_mode}")

    # 选择阈值
    if args.mode == "f1":
        selected_th, selected_idx = th_f1, i_f1
    else:
        selected_th, selected_idx = th_rec, i_rec

    with open(out_th, 'w', encoding='utf-8') as f:
        f.write(str(selected_th))
    print(f"[OK] threshold_fuse.txt = {selected_th:.6f}")

    # 导出曲线与点位
    export_pr_points(prec, rec, th, out_csv)
    draw_pr_curve(prec, rec, th, ap, selected_idx, out_png)

    print(f"[OK] Saved PR curve → {out_png}")
    print(f"[OK] Saved PR points → {out_csv}")
    print("✅ 完成！请重新启动 api.py 查看新阈值与曲线。")

# ========== CLI 入口 ==========
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="通过 API 结果自动校准阈值并生成 PR 曲线")
    ap.add_argument("--url", type=str, default="http://127.0.0.1:8000/predict", help="预测 API 地址")
    ap.add_argument("--n", type=int, default=2000, help="抽样数量")
    ap.add_argument("--mode", choices=["f1","recall"], default="recall", help="阈值选择模式")
    ap.add_argument("--recall_floor", type=float, default=0.98, help="召回率目标（仅 recall 模式有效）")
    args = ap.parse_args()
    main(args)
