// /frontend/frontend/src/components/BatchEvalPanel.tsx
import React, { useMemo, useState } from "react";

type BatchRespItem = {
  label?: "攻击" | "误报";
  score_raw?: number;
  score_final?: number;
  threshold?: number;
  rules?: string[];
  top_terms?: string[];
  flow_score?: number;
  topo_score?: number;
  error?: string;
};

type BatchResp = {
  ok: number;
  err: number;
  pos: number;     // "攻击"
  neg: number;     // "误报"
  unknown?: number; // 新增：后端返回的未知标签统计（可选）
  items: BatchRespItem[];
  threshold?: number;
};

function downloadTextFile(filename: string, content: string) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

// 简单数值格式化
const fmt = (x: unknown, d = 6) => {
  if (x === null || x === undefined) return "-";
  const n = Number(x);
  return Number.isFinite(n) ? n.toFixed(d) : String(x);
};

// 将输入解析为 BatchIn.items
// 支持：
// 1) JSONL：每行一个 alert 对象（或 {"alert":{...}} 对象）；若某行是数组，会被“展开成多条”
// 2) JSON 数组：[{alert: {...}}, ...] 或 简写 [ {...}, {...} ]（会自动包成 {alert: ...}）
// 3) 单个对象：{...} / {"alert": {...}} 也行
function parseBatchInput(raw: string): any[] {
  const trimmed = raw.trim();
  if (!trimmed) return [];

  // 先尝试整体 JSON 解析
  try {
    const v = JSON.parse(trimmed);
    if (Array.isArray(v)) {
      if (v.length === 0) return [];
      // 允许简写：数组内直接是 alert 对象
      if (typeof v[0] === "object" && v[0] !== null && !("alert" in v[0])) {
        return v.map((a: any) => ({ alert: a }));
      }
      return v; // [{alert:...}, ...]
    }
    if (typeof v === "object" && v !== null) {
      // 单个对象
      if ("alert" in v) return [v];
      return [{ alert: v }];
    }
  } catch {
    // 不是合法 JSON → 走 JSONL
  }

  // JSONL: 每行一个 JSON；支持行是对象或数组（数组会展开为多条）
  const lines = trimmed
    .split(/\r?\n/)
    .map(s => s.trim())
    .filter(Boolean)
    // 允许用以 # 开头的注释行
    .filter(s => !s.startsWith("#"));

  const items: any[] = [];
  for (const line of lines) {
    try {
      const obj = JSON.parse(line);
      if (Array.isArray(obj)) {
        for (const a of obj) {
          if (a && typeof a === "object" && !("alert" in a)) {
            items.push({ alert: a });
          } else if (a && typeof a === "object") {
            items.push(a);
          }
        }
      } else if (obj && typeof obj === "object") {
        if ("alert" in obj) items.push(obj);
        else items.push({ alert: obj });
      }
    } catch {
      // 跳过无法解析的行
    }
  }
  return items;
}

export default function BatchEvalPanel({ apiBase }: { apiBase: string }) {
  const [raw, setRaw] = useState<string>(
`# 你可以混合 JSONL 和 JSON 数组；数组行会被展开
{"uri": "/foo?a=1", "rsp_status": "200", "user-agent": "curl/7.79", "confidence":"低", "hazard_rating":"低危"}
{"uri": "/solr/admin/cores?action=STATUS&wt=json", "user-agent": "Go-http-client/1.1"}
[{"uri": "/boaform/admin/formLogin?username=ec8&psd=ec8", "h_method":"GET"}]`
  );
  const [loading, setLoading] = useState<boolean>(false);
  const [err, setErr] = useState<string>("");
  const [res, setRes] = useState<BatchResp | null>(null);

  const url = useMemo(() => `${apiBase.replace(/\/+$/, "")}/batch_predict`, [apiBase]);

  const onRun = async () => {
    setLoading(true);
    setErr("");
    setRes(null);
    try {
      const items = parseBatchInput(raw);
      if (!items.length) {
        setErr("输入为空或无法解析。请粘贴 JSONL / JSON 数组 / 单个对象。");
        setLoading(false);
        return;
      }
      const r = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ items })
      });
      const text = await r.text(); // 先拿文本，兼容非 JSON 错误体
      let d: any = {};
      try { d = JSON.parse(text); } catch { d = { detail: text }; }
      if (!r.ok) {
        setErr(d?.detail || "批量评估失败");
      } else {
        setRes(d);
      }
    } catch (e: any) {
      setErr(String(e?.message || e));
    } finally {
      setLoading(false);
    }
  };

  const toCSV = () => {
    if (!res) return;
    const rows = [
      ["idx","label","score_final","score_raw","threshold","rules","error"]
    ];
    const thGlobal = res.threshold ?? "";
    (res.items || []).forEach((it, i) => {
      rows.push([
        String(i),
        it.label ?? "",
        it.score_final ?? "",
        it.score_raw ?? "",
        it.threshold ?? thGlobal,
        it.rules?.join("|") ?? "",
        it.error ?? ""
      ]);
    });
    const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n");
    downloadTextFile("batch_predict_result.csv", csv);
  };

  const total = (res?.ok ?? 0) + (res?.err ?? 0);
  const acc = res ? ((res.pos + res.neg) / Math.max(1, res.ok)) : 0;

  return (
    <div style={{ background: "#fff", borderRadius: 16, boxShadow: "0 1px 2px rgba(0,0,0,.08)", padding: 16 }}>
      <div style={{ fontWeight: 600, marginBottom: 8 }}>🧪 批量评估 /batch_predict</div>

      <div style={{ fontSize: 12, color: "#64748b", marginBottom: 6 }}>
        支持 JSONL（每行一个对象）或 JSON 数组。对象可简写为直接传 <code>alert</code> 字段；
        若某行是数组，会自动展开成多条。
      </div>

      <textarea
        value={raw}
        onChange={(e) => setRaw(e.target.value)}
        spellCheck={false}
        placeholder={`JSONL 示例：
{"uri": "/foo", "rsp_status":"200"}
{"uri": "/bar", "h_method":"GET"}

JSON 数组示例：
[{"uri": "/foo"}, {"alert": {"uri": "/bar"}}]`}
        style={{
          width: "100%", height: 180, border: "1px solid #e2e8f0", borderRadius: 12,
          padding: 12, fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", fontSize: 13
        }}
      />

      <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
        <button
          onClick={onRun}
          disabled={loading}
          style={{ padding: "8px 12px", borderRadius: 12, background: "#0ea5e9", color: "#fff", border: "none" }}
        >
          {loading ? "评估中..." : "开始评估"}
        </button>
        <button
          onClick={() => { setRes(null); setErr(""); }}
          style={{ padding: "8px 12px", borderRadius: 12, background: "#e2e8f0", color: "#0f172a", border: "none" }}
        >
          清空结果
        </button>
        {res?.items?.length ? (
          <button
            onClick={toCSV}
            style={{ padding: "8px 12px", borderRadius: 12, background: "#10b981", color: "#fff", border: "none" }}
          >
            导出 CSV
          </button>
        ) : null}
      </div>

      {err && <div style={{ color: "#dc2626", marginTop: 8, fontSize: 13 }}>错误：{err}</div>}

      {/* 统计 & 明细 */}
      {res && (
        <div style={{ marginTop: 12 }}>
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap", fontSize: 14 }}>
            <div>总数：<b>{total}</b></div>
            <div>OK：<b>{res.ok}</b></div>
            <div>ERR：<b>{res.err}</b></div>
            <div>攻击（pos）：<b style={{ color: "#dc2626" }}>{res.pos}</b></div>
            <div>误报（neg）：<b style={{ color: "#16a34a" }}>{res.neg}</b></div>
            {typeof res.unknown === "number" && <div>未知（unknown）：<b>{res.unknown}</b></div>}
            <div>阈值：<b>{res.threshold ?? "-"}</b></div>
            <div>准确率（OK 内）：<b>{fmt(acc, 3)}</b></div>
          </div>

          <div style={{ marginTop: 8, overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ background: "#f1f5f9" }}>
                  <th style={{ textAlign: "left", padding: 8, borderBottom: "1px solid #e2e8f0" }}>#</th>
                  <th style={{ textAlign: "left", padding: 8, borderBottom: "1px solid #e2e8f0" }}>label</th>
                  <th style={{ textAlign: "right", padding: 8, borderBottom: "1px solid #e2e8f0" }}>score_final</th>
                  <th style={{ textAlign: "right", padding: 8, borderBottom: "1px solid #e2e8f0" }}>score_raw</th>
                  <th style={{ textAlign: "right", padding: 8, borderBottom: "1px solid #e2e8f0" }}>threshold</th>
                  <th style={{ textAlign: "left", padding: 8, borderBottom: "1px solid #e2e8f0" }}>rules</th>
                  <th style={{ textAlign: "left", padding: 8, borderBottom: "1px solid #e2e8f0" }}>error</th>
                </tr>
              </thead>
              <tbody>
                {(res.items || []).map((it, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid #e2e8f0" }}>
                    <td style={{ padding: 8 }}>{i}</td>
                    <td style={{ padding: 8, color: it.label === "攻击" ? "#dc2626" : "#16a34a" }}>
                      {it.label ?? "-"}
                    </td>
                    <td style={{ padding: 8, textAlign: "right" }}>{fmt(it.score_final)}</td>
                    <td style={{ padding: 8, textAlign: "right" }}>{fmt(it.score_raw)}</td>
                    <td style={{ padding: 8, textAlign: "right" }}>{fmt(it.threshold ?? (res.threshold ?? "-"))}</td>
                    <td style={{ padding: 8 }}>
                      {it.rules?.length ? it.rules.join(" | ") : ""}
                    </td>
                    <td style={{ padding: 8, color: "#dc2626" }}>{it.error ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

        </div>
      )}
    </div>
  );
}
