import React, { useEffect, useMemo, useState } from "react";

type Meta = {
  status: string;
  threshold?: number | null;
  fuser_loaded?: boolean;
  use_logit?: boolean;
  fuse_recall_pref?: Record<string, unknown>;
};

type Health = {
  ok: boolean;
  scorer_error?: string;
  threshold?: number | null;
};

export default function MetaPanel({ apiBase }: { apiBase: string }) {
  const base = useMemo(() => apiBase.replace(/\/+$/, ""), [apiBase]);
  const metaUrl = useMemo(() => `${base}/meta`, [base]);
  const healthUrl = useMemo(() => `${base}/health`, [base]);

  const [meta, setMeta] = useState<Meta | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [err, setErr] = useState<string>("");

  const fetchAll = async () => {
    setLoading(true);
    setErr("");
    try {
      const [m, h] = await Promise.all([
        fetch(metaUrl).then(r => r.json()),
        fetch(healthUrl).then(r => r.json())
      ]);
      setMeta(m);
      setHealth(h);
    } catch (e: any) {
      setErr(String(e?.message || e));
      setMeta(null);
      setHealth(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchAll(); /* eslint-disable-next-line */ }, [metaUrl, healthUrl]);

  const currentThreshold =
    meta?.threshold != null ? meta?.threshold : health?.threshold ?? "-";

  const Badge = ({ ok, text }: { ok: boolean; text: string }) => (
    <span
      style={{
        padding: "2px 8px",
        borderRadius: 9999,
        fontSize: 12,
        background: ok ? "#ecfdf5" : "#fef2f2",
        color: ok ? "#065f46" : "#991b1b",
        border: `1px solid ${ok ? "#d1fae5" : "#fee2e2"}`
      }}
    >
      {text}
    </span>
  );

  return (
    <div
      style={{
        background: "#fff",
        borderRadius: 16,
        boxShadow: "0 1px 2px rgba(0,0,0,.08)",
        padding: 16
      }}
    >
      <div style={{ fontWeight: 600, marginBottom: 8 }}>模型状态</div>

      <div style={{ fontSize: 14, display: "grid", gap: 6 }}>
        <div>
          后端：
          <b>{meta?.status || "-"}</b>{" "}
          <Badge ok={!!health?.ok} text={health?.ok ? "healthy" : "unhealthy"} />
        </div>
        <div>
          当前阈值：<b>{currentThreshold as any}</b>
        </div>
        <div>
          融合器：<b>{meta?.fuser_loaded ? "已加载" : "未加载"}</b>　
          |　二层使用 logit：<b>{meta?.use_logit ? "是" : "否"}</b>
        </div>
      </div>

      {health?.scorer_error && (
        <div
          style={{
            color: "#dc2626",
            marginTop: 8,
            fontSize: 12,
            whiteSpace: "pre-wrap"
          }}
        >
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Scorer 载入错误</div>
          {health.scorer_error}
        </div>
      )}

      {err && (
        <div style={{ color: "#dc2626", marginTop: 8, fontSize: 13 }}>
          错误：{err}
        </div>
      )}

      <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
        <button
          onClick={fetchAll}
          disabled={loading}
          style={{
            padding: "6px 12px",
            borderRadius: 12,
            background: "#0f172a",
            color: "#fff",
            border: "none",
            fontSize: 13
          }}
        >
          {loading ? "刷新中..." : "刷新状态"}
        </button>
      </div>
    </div>
  );
}
