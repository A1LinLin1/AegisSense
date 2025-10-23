# api.py
# -*- coding: utf-8 -*-
import os, json, traceback
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel

from routes_extra import router as extra_router



# ---------- 你的打分逻辑 ----------
try:
    from scorer import score_alert
    SCORER_OK = True
    SCORER_ERR = ""
except Exception as e:
    SCORER_OK = False
    SCORER_ERR = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"

app = FastAPI(title="Alert Noise Reduction API", version="1.2.0")
app.include_router(extra_router)
# CORS：生产用白名单（环境变量 ALLOWED_ORIGINS="https://a.com,https://b.com"）
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 静态目录（放 PR 曲线、CSV）
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ---------- Pydantic ----------
class PredictIn(BaseModel):
    alert: Any
    flow: Optional[Dict[str, Any]] = None
    topo: Optional[Dict[str, Any]] = None

class BatchItem(BaseModel):
    alert: Any
    flow: Optional[Dict[str, Any]] = None
    topo: Optional[Dict[str, Any]] = None

class BatchIn(BaseModel):
    items: List[BatchItem]

class CalibrateIn(BaseModel):
    n: int = 2000
    mode: str = "recall"   # "f1" or "recall"
    recall_floor: float = 0.98


# ---------- 输入解析（严格 400） ----------
def parse_alert(x: Any) -> Dict[str, Any]:
    if isinstance(x, dict):
        return x
    if isinstance(x, str):
        try:
            v = json.loads(x)
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f"alert is not valid JSON: {e}")
        if not isinstance(v, dict):
            raise HTTPException(status_code=400, detail="alert must be a JSON object")
        return v
    raise HTTPException(status_code=400, detail="alert must be object or JSON string")


# ---------- 工具 ----------
def _read_threshold() -> Optional[float]:
    for name in ("threshold_fuse.txt", "threshold.txt"):
        p = os.path.join(os.path.dirname(__file__), name)
        if os.path.exists(p):
            try:
                return float(open(p, "r", encoding="utf-8").read().strip())
            except Exception:
                pass
    return None

def _meta_fuser() -> Dict[str, Any]:
    meta = {}
    use_logit = False
    try:
        p = os.path.join(os.path.dirname(__file__), "fuser_metrics.json")
        if os.path.exists(p):
            meta = json.load(open(p, "r", encoding="utf-8"))
            use_logit = bool(meta.get("args", {}).get("use_logit", False))
    except Exception:
        meta = {}
        use_logit = False

    fuser_loaded = False
    try:
        import joblib
        joblib.load(os.path.join(os.path.dirname(__file__), "rule_fuser.pkl"))
        fuser_loaded = True
    except Exception:
        fuser_loaded = False

    return {
        "fuser_loaded": fuser_loaded,
        "use_logit": use_logit,
        "fuse_recall_pref": meta.get("fuse_recall_pref", {}),
    }


# ---------- 健康 / 元信息 ----------
@app.get("/health")
def health() -> Dict[str, Any]:
    calibrate_ready = True
    try:
        import numpy; import sklearn; import matplotlib; import datasets  # noqa: F401
    except Exception:
        calibrate_ready = False
    expose = os.getenv("EXPOSE_ERRORS", "0") == "1"
    return {
        "ok": SCORER_OK,
        "scorer_error": SCORER_ERR if (not SCORER_OK and expose) else "",
        "threshold": _read_threshold(),
        "static_dir": STATIC_DIR,
        "calibrate_ready": calibrate_ready,
    }

@app.get("/meta")
def meta() -> Dict[str, Any]:
    status = "ready" if SCORER_OK else "scorer_load_failed"
    m = _meta_fuser()
    return {"status": status, "threshold": _read_threshold(), **m}


# ---------- 预测 ----------
@app.post("/predict")
def predict(inp: PredictIn) -> Dict[str, Any]:
    if not SCORER_OK:
        raise HTTPException(status_code=500, detail=f"scorer init failed: {SCORER_ERR}")
    alert_obj = parse_alert(inp.alert)
    try:
        out = score_alert(alert_obj, flow=inp.flow, topo=inp.topo)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"predict failed: {type(e).__name__}: {e}")
    # 注意：score_alert 内部已动态读取阈值并产出 label/threshold
    return jsonable_encoder(out)

@app.post("/batch_predict")
def batch_predict(batch: BatchIn) -> Dict[str, Any]:
    if not SCORER_OK:
        raise HTTPException(status_code=500, detail=f"scorer init failed: {SCORER_ERR}")
    results: List[Dict[str, Any]] = []
    ok = err = pos = neg = unknown = 0
    for it in batch.items:
        try:
            a = parse_alert(it.alert)
        except HTTPException as e:
            results.append({"error": f"{e.detail}"})
            err += 1
            continue
        try:
            r = score_alert(a, flow=it.flow, topo=it.topo)
            results.append(jsonable_encoder(r)); ok += 1
            lbl = r.get("label")
            if lbl == "攻击": pos += 1
            elif lbl == "误报": neg += 1
            else: unknown += 1
        except Exception as e:
            results.append({"error": f"{type(e).__name__}: {e}"}); err += 1
    return {"ok": ok, "err": err, "pos": pos, "neg": neg, "unknown": unknown, "items": results, "threshold": _read_threshold()}


# ---------- 阈值校准 /calibrate ----------
@app.post("/calibrate")
def calibrate(inp: CalibrateIn) -> Dict[str, Any]:
    """
    服务端校准：
    - 抽样 N 条数据
    - 计算 PR/AP
    - 选择 F1* 或 recall_floor 的最佳阈值
    - 写入 threshold_fuse.txt
    - 导出 PR 曲线 PNG 与 CSV 到 static/
    """
    if not SCORER_OK:
        raise HTTPException(status_code=500, detail=f"scorer init failed: {SCORER_ERR}")

    # 惰性导入
    try:
        import numpy as np
        from datasets import load_dataset
        from sklearn.metrics import precision_recall_curve, average_precision_score
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dependencies missing: {type(e).__name__}: {e}")

    N = max(50, int(inp.n))
    mode = inp.mode.lower()
    recall_floor = float(inp.recall_floor)

    # 加载数据（可扩展为本地 CSV）
    try:
        ds = load_dataset("tiangler/cybersecurity_alarm_analysis")
        X = ds['train']['input'][:N]
        y = ds['train']['output'][:N]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"load_dataset failed: {type(e).__name__}: {e}")

    y_true = (np.array(y) == '攻击').astype(int)

    # 逐条打分（走内部 score_alert，包含你的融合/规则逻辑）
    scores = []
    for a in X:
        try:
            s = score_alert(a).get("score_final")
            if s is None:
                s = score_alert(a).get("score_raw", 0.0)
            scores.append(float(s))
        except Exception:
            scores.append(0.0)
    scores = np.array(scores, dtype=float)
    y_true = y_true[:len(scores)]

    # 计算 PR / AP
    try:
        ap = float(average_precision_score(y_true, scores))
        prec, rec, th = precision_recall_curve(y_true, scores)
        if len(th) == 0:
            # 退化场景兜底：用中位数阈值
            selected_th = float(np.median(scores))
            sel_mode = "fallback_median"
            i_sel = max(0, np.argmax(rec))  # 放一个点位
            px, rx = float(prec[i_sel]), float(rec[i_sel])
        else:
            F1 = 2*prec[:-1]*rec[:-1]/(prec[:-1]+rec[:-1]+1e-12)
            i_f1 = int(np.nanargmax(F1))
            th_f1 = float(th[i_f1]); Pf1 = float(prec[i_f1]); Rf1 = float(rec[i_f1]); Ff1 = float(F1[i_f1])

            mask = (rec[:-1] >= recall_floor)
            if np.any(mask):
                cand_idx = np.where(mask)[0]
                i_rec = int(cand_idx[np.argmax(prec[:-1][mask])])
                th_rec = float(th[i_rec]); Prec_rec = float(prec[i_rec]); Rec_rec = float(rec[i_rec])
                sel_mode = "recall_target"
            else:
                th_rec, Prec_rec, Rec_rec, sel_mode = th_f1, Pf1, Rf1, "fallback_f1"
                i_rec = i_f1

            if mode == "f1":
                selected_th, i_sel = th_f1, i_f1
            else:
                selected_th, i_sel = th_rec, i_rec
            px, rx = float(prec[i_sel]), float(rec[i_sel])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"metrics failed: {type(e).__name__}: {e}")

    # 写阈值
    out_th = os.path.join(os.path.dirname(__file__), "threshold_fuse.txt")
    try:
        with open(out_th, 'w', encoding='utf-8') as f:
            f.write(str(selected_th))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"write threshold failed: {type(e).__name__}: {e}")

    # 导出 PR 全量点位 CSV（prec/rec 无 threshold）
    out_csv = os.path.join(STATIC_DIR, "pr_points_api.csv")
    try:
        with open(out_csv, "w", encoding="utf-8") as f:
            f.write("precision,recall\n")
            for p, r in zip(prec, rec):
                f.write(f"{p},{r}\n")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"write csv failed: {type(e).__name__}: {e}")

    # 绘制 PR 曲线 PNG
    out_png = os.path.join(STATIC_DIR, "pr_curve_api.png")
    try:
        import matplotlib.pyplot as plt
        plt.figure(figsize=(7, 5))
        plt.plot(rec, prec, lw=2, label=f"PR curve (AP={ap:.4f})")
        plt.scatter([rx], [px], s=60, c='red', label=f"selected (P={px:.3f}, R={rx:.3f})")
        plt.xlabel("Recall"); plt.ylabel("Precision")
        plt.title("Precision-Recall Curve (service-side calibration)")
        plt.grid(True, linestyle='--', alpha=0.4)
        plt.legend(loc="lower left"); plt.tight_layout()
        plt.savefig(out_png, dpi=160); plt.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"save png failed: {type(e).__name__}: {e}")

    return {
        "ok": True,
        "ap": ap,
        "selected": {"mode": mode, "threshold": selected_th},
        "artifacts": {
            "threshold_file": out_th,
            "pr_curve_png": f"/static/{os.path.basename(out_png)}",
            "pr_points_csv": f"/static/{os.path.basename(out_csv)}",
        }
    }


# ---------- main ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=False)
