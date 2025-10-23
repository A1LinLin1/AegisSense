import React, { useEffect, useMemo, useRef, useState } from "react";

/** ------- 小工具 ------- */
const pct = (x: number) => (x * 100).toFixed(1) + "%";
const num = (x: any) => (x == null ? "-" : x.toLocaleString?.() ?? String(x));

/** 基于 24h 趋势的简单异常检测：均值+标准差，超过均值+2.0σ 认为异常峰值 */
function detectAnomaly(values: number[]) {
  if (!values?.length) return null;
  const n = values.length;
  const mean = values.reduce((a, b) => a + b, 0) / n;
  const sd = Math.sqrt(values.reduce((s, v) => s + (v - mean) ** 2, 0) / Math.max(1, n - 1));
  const thr = mean + 2.0 * sd;
  let idx = -1, peak = -Infinity;
  values.forEach((v, i) => {
    if (v > thr && v > peak) { peak = v; idx = i; }
  });
  return idx >= 0 ? { index: idx, value: peak, mean, sd, thr } : null;
}

/** ------- 折线图（含面积 & 悬停） ------- */
function LineChart({
  data,
  width = 640,
  height = 220,
  padding = 28,
  title,
  formatX = (i: number) => `${i}h`,
  formatY = (v: number) => String(Math.round(v)),
}: {
  data: number[];
  width?: number;
  height?: number;
  padding?: number;
  title?: string;
  formatX?: (i: number) => string;
  formatY?: (v: number) => string;
}) {
  const [hover, setHover] = useState<{ i: number; x: number; y: number } | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  if (!data?.length) return <div className="muted">暂无数据</div>;
  const W = width, H = height, P = padding, n = data.length;

  const min = Math.min(...data);
  const max = Math.max(...data);
  const yLo = Math.floor(min);
  const yHi = Math.ceil(max || 1);

  const x = (i: number) => P + (i * (W - 2 * P)) / (Math.max(1, n - 1));
  const y = (v: number) => H - P - ((v - yLo) * (H - 2 * P)) / (yHi - yLo || 1);

  const path = data.map((v, i) => `${i ? "L" : "M"} ${x(i)} ${y(v)}`).join(" ");
  const area = `${path} L ${x(n - 1)} ${H - P} L ${x(0)} ${H - P} Z`;

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;
    const px = e.clientX - rect.left;
    let i = Math.round(((px - P) / (W - 2 * P)) * (n - 1));
    i = Math.max(0, Math.min(n - 1, i));
    setHover({ i, x: x(i), y: y(data[i]) });
  };

  return (
    <div style={{ position: "relative" }}>
      {title && <div className="card__title" style={{ marginBottom: 4 }}>{title}</div>}
      <svg
        ref={svgRef}
        width="100%"
        viewBox={`0 0 ${W} ${H}`}
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
        style={{ display: "block" }}
      >
        {/* 背景网格 */}
        {[0, 0.25, 0.5, 0.75, 1].map((t, idx) => {
          const yy = H - P - t * (H - 2 * P);
          const vv = yLo + t * (yHi - yLo);
          return (
            <g key={idx}>
              <line x1={P} y1={yy} x2={W - P} y2={yy} stroke="#e2e8f0" strokeDasharray="4 4" />
              <text x={P - 6} y={yy} dy="0.32em" textAnchor="end" fill="#64748b" fontSize="10">
                {formatY(vv)}
              </text>
            </g>
          );
        })}

        {/* X 端点标注 */}
        <text x={P} y={H - P + 14} fill="#64748b" fontSize="10">{formatX(0)}</text>
        <text x={W - P} y={H - P + 14} fill="#64748b" fontSize="10" textAnchor="end">
          {formatX(n - 1)}
        </text>

        {/* 面积 & 折线 */}
        <path d={area} fill="#0ea5e9" opacity="0.12" />
        <path d={path} fill="none" stroke="#0ea5e9" strokeWidth="2.2" />

        {/* 悬停 */}
        {hover && (
          <>
            <line x1={hover.x} y1={P} x2={hover.x} y2={H - P} stroke="#94a3b8" strokeDasharray="3 3" />
            <circle cx={hover.x} cy={hover.y} r={4} fill="#0ea5e9" stroke="#fff" strokeWidth="2" />
          </>
        )}
      </svg>

      {/* 提示框 */}
      {hover && (
        <div
          className="chart-tooltip"
          style={{
            position: "absolute",
            left: `${(hover.x / W) * 100}%`,
            top: `${((hover.y - 10) / H) * 100}%`,
            transform: "translate(-50%, -100%)",
          }}
        >
          <div className="chart-tooltip__inner">
            <div style={{ fontWeight: 600 }}>{formatX(hover.i)}</div>
            <div>请求数：{num(data[hover.i])}</div>
          </div>
        </div>
      )}
    </div>
  );
}

/** ------- 环形图（Donut） ------- */
function DonutChart({
  title,
  data,
  labelKey = "label",
  valueKey = "count",
  size = 180,
  innerRatio = 0.62,
  colors = ["#3b82f6", "#22c55e", "#f59e0b", "#ef4444", "#8b5cf6", "#0ea5e9"],
}: {
  title: string;
  data: any[];
  labelKey?: string;
  valueKey?: string;
  size?: number;
  innerRatio?: number;
  colors?: string[];
}) {
  if (!data?.length) return <div className="muted">暂无数据</div>;
  const total = data.reduce((s, d) => s + Number(d[valueKey] || 0), 0) || 1;
  const R = size / 2;
  const r = R * innerRatio;
  const cx = R, cy = R;

  let acc = 0;
  const arcs = data.map((d, i) => {
    const v = Number(d[valueKey] || 0);
    const start = acc / total; acc += v;
    const end = acc / total;
    const a0 = -Math.PI / 2 + 2 * Math.PI * start;
    const a1 = -Math.PI / 2 + 2 * Math.PI * end;

    const p0o = [cx + R * Math.cos(a0), cy + R * Math.sin(a0)];
    const p1o = [cx + R * Math.cos(a1), cy + R * Math.sin(a1)];
    const p0i = [cx + r * Math.cos(a0), cy + r * Math.sin(a0)];
    const p1i = [cx + r * Math.cos(a1), cy + r * Math.sin(a1)];
    const large = end - start > 0.5 ? 1 : 0;

    const dPath = [
      `M ${p0o[0]} ${p0o[1]}`,
      `A ${R} ${R} 0 ${large} 1 ${p1o[0]} ${p1o[1]}`,
      `L ${p1i[0]} ${p1i[1]}`,
      `A ${r} ${r} 0 ${large} 0 ${p0i[0]} ${p0i[1]}`,
      "Z",
    ].join(" ");

    return (
      <path
        key={i}
        d={dPath}
        fill={colors[i % colors.length]}
        stroke="#fff"
        strokeWidth={1}
      />
    );
  });

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        {arcs}
        {/* 中心文本 */}
        <text x={cx} y={cy - 4} textAnchor="middle" fontSize="13" fill="#0f172a" fontWeight={700}>
          {title}
        </text>
        <text x={cx} y={cy + 14} textAnchor="middle" fontSize="11" fill="#64748b">
          {num(total)}
        </text>
      </svg>
      {/* 图例 */}
      <div>
        <div className="card__title" style={{ marginBottom: 4 }}>{title}（前 {Math.min(6, data.length)}）</div>
        {data.slice(0, 6).map((d, i) => (
          <div key={i} className="row gap-8" style={{ alignItems: "center", fontSize: 12, marginBottom: 6 }}>
            <div style={{ width: 12, height: 12, background: colors[i % colors.length], borderRadius: 2 }} />
            <div style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {d[labelKey]}
            </div>
            <div>{num(d[valueKey])}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

/** ------- 水平条形图（Top 国家/地区） ------- */
function HBarChart({
  title,
  data,
  labelKey = "country",
  valueKey = "count",
  maxBars = 8,
}: {
  title: string;
  data: any[];
  labelKey?: string;
  valueKey?: string;
  maxBars?: number;
}) {
  if (!data?.length) return <div className="muted">暂无数据</div>;
  const rows = data.slice(0, maxBars);
  const max = Math.max(...rows.map((r: any) => Number(r[valueKey] || 0)), 1);

  return (
    <div>
      <div className="card__title" style={{ marginBottom: 4 }}>{title}</div>
      <div style={{ display: "grid", gap: 8 }}>
        {rows.map((r: any, i: number) => {
          const v = Number(r[valueKey] || 0);
          return (
            <div key={i}>
              <div className="row" style={{ justifyContent: "space-between", fontSize: 12, marginBottom: 4 }}>
                <div style={{ color: "#334155" }}>{r[labelKey]}</div>
                <div style={{ color: "#64748b" }}>{num(v)}</div>
              </div>
              <div style={{ height: 8, background: "#e2e8f0", borderRadius: 9999 }}>
                <div
                  style={{
                    width: `${(v / max) * 100}%`,
                    height: 8,
                    borderRadius: 9999,
                    background: "linear-gradient(90deg, #0ea5e9 0%, #6366f1 100%)",
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/** ------- 主组件：Dashboard ------- */
export default function Dashboard({ apiBase }: { apiBase: string }) {
  const url = useMemo(() => `${apiBase.replace(/\/+$/, "")}/overview`, [apiBase]);
  const [data, setData] = useState<any>(null);
  const [err, setErr] = useState<string>("");

  useEffect(() => {
    (async () => {
      try {
        const r = await fetch(url);
        setData(await r.json());
      } catch (e: any) {
        setErr(String(e?.message || e));
      }
    })();
  }, [url]);

  if (err) return <div className="error">错误：{err}</div>;
  if (!data) return <div className="muted">加载中...</div>;

  const trend: number[] = data.trend_24h || [];
  const anomaly = detectAnomaly(trend);

  // Top 数据映射
  const topURI = (data.top_uri || []).map((x: any) => ({ label: x.uri, count: x.count }));
  const topUA = (data.top_ua || []).map((x: any) => ({ label: x.ua, count: x.count }));
  const geo = data.geo_heat || [];

  return (
    <div className="grid grid--2">
      {/* KPI 卡片 */}
      <div className="card">
        <div className="card__title">今日 KPI</div>
        <div className="row gap-8" style={{ flexWrap: "wrap" }}>
          <div>总量：<b>{num(data.today.total)}</b></div>
          <div>攻击率：<b>{pct(data.today.attack_rate)}</b></div>
          <div>拦截率：<b>{pct(data.today.blocked_rate)}</b></div>
          <div>TP：<b>{num(data.kpi.tp)}</b></div>
          <div>FP：<b>{num(data.kpi.fp)}</b></div>
          <div>FN：<b className="text-danger">{num(data.kpi.fn)}</b></div>
        </div>
        {anomaly && (
          <div className="chips" style={{ marginTop: 10 }}>
            <span className="chip chip--warn">
              异常峰值：{anomaly.index}h → {num(anomaly.value)}（阈值≈{Math.round(anomaly.thr)})
            </span>
          </div>
        )}
      </div>

      {/* 24h 趋势 */}
      <div className="card">
        <LineChart
          data={trend}
          title="过去 24 小时趋势"
          width={640}
          height={220}
        />
      </div>

      {/* Top URI Donut */}
      <div className="card">
        <DonutChart title="Top URI" data={topURI} />
      </div>

      {/* Top UA Donut */}
      <div className="card">
        <DonutChart title="Top UA" data={topUA} />
      </div>

      {/* 地理分布（水平条形） */}
      <div className="card">
        <HBarChart title="来源国家/地区" data={geo} />
      </div>

      {/* 预留：顶部来源 IP / Top 攻击类型（后端扩展字段即可直接喂给 Donut/HBar） */}
      <div className="card">
        <div className="card__title">提示</div>
        <div className="note">
          若后端 `/overview` 增加 <code>top_src_ip</code> 或 <code>top_attack_type</code> 字段，
          这里可以直接复用 <b>DonutChart</b> 或 <b>HBarChart</b> 展示。
        </div>
      </div>
    </div>
  );
}
