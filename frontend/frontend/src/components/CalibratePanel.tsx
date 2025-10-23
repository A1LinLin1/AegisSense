// frontend/frontend/src/components/CalibratePanel.tsx
import React, { useMemo, useState } from "react";

type F1Star = { th: number; P: number; R: number; F1: number };
type RecallPref = { th: number; P: number; R: number; mode: string; recall_floor: number };

// 兼容两种返回：老版含 f1_star/recall_pref，新版不含
type CalibrateResp = {
  ok: boolean;
  ap: number;
  selected: { mode: "f1" | "recall"; threshold: number };
  artifacts: { threshold_file: string; pr_curve_png: string; pr_points_csv: string };
  f1_star?: F1Star;
  recall_pref?: RecallPref;
};

export default function CalibratePanel({ apiBase }: { apiBase: string }) {
  const [n, setN] = useState<number>(2000);
  const [mode, setMode] = useState<"f1" | "recall">("recall");
  const [recallFloor, setRecallFloor] = useState<number>(0.98);
  const [loading, setLoading] = useState<boolean>(false);
  const [err, setErr] = useState<string>("");
  const [res, setRes] = useState<CalibrateResp | null>(null);
  const [ts, setTs] = useState<number>(Date.now()); // 刷新 PR 图缓存

  const base = useMemo(() => apiBase.replace(/\/+$/, ""), [apiBase]);
  const url = useMemo(() => `${base}/calibrate`, [base]);
  const prImg = useMemo(() => `${base}/static/pr_curve_api.png?ts=${ts}`, [base, ts]);

  const onCalibrate = async () => {
    const N = Math.max(50, Number.isFinite(n) ? n : 50);
    setLoading(true);
    setErr("");
    setRes(null);
    try {
      const r = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ n: N, mode, recall_floor: recallFloor })
      });
      const text = await r.text();
      let d: any;
      try { d = JSON.parse(text); } catch { d = { detail: text }; }
      if (!r.ok) {
        setErr(d?.detail || "标定失败");
      } else {
        setRes(d);
        setTs(Date.now()); // 刷新 PR 图
      }
    } catch (e: any) {
      setErr(String(e?.message || e));
    } finally {
      setLoading(false);
    }
  };

  const pretty = (x: unknown) => {
    try { return JSON.stringify(x, null, 2); } catch { return String(x); }
  };

  return (
    <div style={{ background: "#fff", borderRadius: 16, boxShadow: "0 1px 2px rgba(0,0,0,.08)", padding: 16 }}>
      <div style={{ fontWeight: 600, marginBottom: 8 }}>⚙️ 阈值标定（服务端）</div>

      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontSize: 12, color: "#64748b" }}>抽样 N</div>
          <input
            type="number" min={50} step={50}
            value={n}
            onChange={(e) => {
              const v = parseInt(e.target.value || "0", 10);
              setN(Number.isFinite(v) ? v : 50);
            }}
            style={{ width: 120, border: "1px solid #e2e8f0", borderRadius: 10, padding: 8 }}
          />
        </div>

        <div>
          <div style={{ fontSize: 12, color: "#64748b" }}>模式</div>
          <select
            value={mode}
            onChange={(e) => setMode(e.target.value as "f1" | "recall")}
            style={{ width: 140, border: "1px solid #e2e8f0", borderRadius: 10, padding: 8, background: "#fff" }}
          >
            <option value="f1">F1 最优</option>
            <option value="recall">召回优先</option>
          </select>
        </div>

        <div>
          <div style={{ fontSize: 12, color: "#64748b" }}>召回下限 (recall_floor)</div>
          <input
            type="number" step={0.001} min={0} max={1}
            value={recallFloor}
            onChange={(e) => setRecallFloor(parseFloat(e.target.value || "0"))}
            style={{ width: 160, border: "1px solid #e2e8f0", borderRadius: 10, padding: 8 }}
            disabled={mode !== "recall"}
            title={mode !== "recall" ? "在 '召回优先' 模式下可编辑" : ""}
          />
        </div>

        <div style={{ alignSelf: "flex-end" }}>
          <button
            onClick={onCalibrate}
            disabled={loading}
            style={{ padding: "8px 12px", borderRadius: 12, background: "#7c3aed", color: "#fff", border: "none" }}
          >
            {loading ? "标定中..." : "开始标定"}
          </button>
        </div>
      </div>

      {err && <div style={{ color: "#dc2626", marginTop: 8, fontSize: 13 }}>错误：{err}</div>}

      {res && (
        <div style={{ marginTop: 12 }}>
          <div style={{ fontSize: 14, lineHeight: 1.6 }}>
            <div>PR-AUC：<b>{Number(res.ap).toFixed(4)}</b></div>
            <div>选择模式：<b>{res.selected.mode}</b>，新阈值：<b>{Number(res.selected.threshold).toFixed(6)}</b></div>
          </div>

          {/* 仅当后端返回时才显示这两块 */}
          {(res.f1_star || res.recall_pref) && (
            <div style={{ marginTop: 8, display: "grid", gap: 12, gridTemplateColumns: "1fr 1fr" }}>
              {res.f1_star && (
                <div>
                  <div style={{ fontSize: 12, color: "#64748b" }}>F1★</div>
                  <pre style={{ whiteSpace: "pre-wrap", background: "#f8fafc", border: "1px solid #e2e8f0", borderRadius: 12, padding: 10 }}>
{pretty(res.f1_star)}
                  </pre>
                </div>
              )}
              {res.recall_pref && (
                <div>
                  <div style={{ fontSize: 12, color: "#64748b" }}>Recall 优先</div>
                  <pre style={{ whiteSpace: "pre-wrap", background: "#f8fafc", border: "1px solid #e2e8f0", borderRadius: 12, padding: 10 }}>
{pretty(res.recall_pref)}
                  </pre>
                </div>
              )}
            </div>
          )}

          <div style={{ marginTop: 12 }}>
            <div style={{ fontSize: 12, color: "#64748b", marginBottom: 6 }}>PR 曲线</div>
            <img
              src={prImg}
              alt="PR Curve"
              style={{ width: "100%", maxWidth: 780, border: "1px solid #e2e8f0", borderRadius: 12 }}
            />
          </div>

          <div style={{ fontSize: 12, color: "#64748b", marginTop: 8 }}>
            产物：
            <code className="mx-2">{res.artifacts.threshold_file}</code>
            　·　
            <a href={`${base}${res.artifacts.pr_points_csv}`} target="_blank" rel="noreferrer">
              pr_points_api.csv
            </a>
          </div>
        </div>
      )}
    </div>
  );
}
