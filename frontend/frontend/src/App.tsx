// frontend/frontend/src/App.tsx
import React, { useMemo, useState } from "react";
import MetaPanel from "./components/MetaPanel";
import CalibratePanel from "./components/CalibratePanel";
import BatchEvalPanel from "./components/BatchEvalPanel";
import Dashboard from "./components/Dashboard";
import AlertTriage from "./components/AlertTriage";
import RulesReport from "./components/RulesReport";
import AssetFlowPanel from "./components/AssetFlowPanel";
import "./App.css";

/** 单条预测返回结构（补充了可选 id/asset_id 以便资产与流量联动） */
type PredictResp = {
  id?: number;                 // 可选：若后端返回告警id
  asset_id?: number | null;    // 可选：资产id（用于资产/流量联动）
  label: "攻击" | "误报";
  score_raw?: number;
  score_final?: number;
  threshold?: number;
  rules?: string[];
  top_terms?: string[];
  flow_score?: number;
  topo_score?: number;
};

const fmt = (x: unknown, d = 6) => {
  if (x === null || x === undefined) return "-";
  const n = Number(x);
  return Number.isFinite(n) ? n.toFixed(d) : String(x);
};

type TabKey = "overview" | "triage" | "predict" | "batch" | "calibrate" | "report";

export default function App() {
  const [apiBase, setApiBase] = useState<string>("http://127.0.0.1:8000");
  const [active, setActive] = useState<TabKey>("overview");

  // 单条预测
  const [singleJson, setSingleJson] = useState<string>(
`{
  "uri": "/gateway/support/oss/getPublicInputStream?filePath=/etc/anacrontab",
  "rsp_status": "200",
  "rsp_body": "{\\"code\\":500,\\"message\\":\\"非法路径，该接口仅提供public目录下文件流获取\\"}",
  "user-agent": "Mozilla/5.0",
  "confidence": "中",
  "hazard_rating": "低危"
}`
  );
  const [singleLoading, setSingleLoading] = useState<boolean>(false);
  const [singleRes, setSingleRes] = useState<PredictResp | null>(null);
  const [singleErr, setSingleErr] = useState<string>("");

  const predictUrl = useMemo(
    () => `${apiBase.replace(/\/+$/, "")}/predict`,
    [apiBase]
  );

  const doPredict = async () => {
    setSingleErr("");
    setSingleRes(null);
    let obj: any;
    try {
      obj = JSON.parse(singleJson);
    } catch {
      setSingleErr("请输入合法 JSON 对象。");
      return;
    }
    setSingleLoading(true);
    try {
      const r = await fetch(predictUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // 注意：后端 api.py 已去掉 embed=True，这里直接传 {alert}
        body: JSON.stringify({ alert: obj })
      });
      const d = await r.json();
      if (!r.ok) {
        setSingleErr(d?.detail || "预测失败");
      } else {
        setSingleRes(d);
      }
    } catch (e: any) {
      setSingleErr(String(e?.message || e));
    } finally {
      setSingleLoading(false);
    }
  };

  return (
    <div className="page">
      {/* 顶部 Hero */}
      <header className="hero">
        <div className="hero__inner">
          <div className="hero__title">WAF/IDS 日志分析控制台</div>
          <div className="hero__sub">总览态势 · 工作台 · 实时预测 · 批量评估 · 阈值校准 · 规则报表</div>
        </div>
      </header>

      {/* 顶部工具条：API 地址 + 页签 */}
      <div className="toolbar">
        <div className="toolbar__left">
          <label className="toolbar__label">API 地址</label>
          <input
            value={apiBase}
            onChange={(e) => setApiBase(e.target.value)}
            className="input toolbar__input"
            placeholder="http://127.0.0.1:8000"
          />
        </div>

        <nav className="tabs">
          <button
            className={`tab ${active === "overview" ? "tab--active" : ""}`}
            onClick={() => setActive("overview")}
          >
            总览
          </button>
          <button
            className={`tab ${active === "triage" ? "tab--active" : ""}`}
            onClick={() => setActive("triage")}
          >
            工作台
          </button>
          <button
            className={`tab ${active === "predict" ? "tab--active" : ""}`}
            onClick={() => setActive("predict")}
          >
            实时预测
          </button>
          <button
            className={`tab ${active === "batch" ? "tab--active" : ""}`}
            onClick={() => setActive("batch")}
          >
            批量评估
          </button>
          <button
            className={`tab ${active === "calibrate" ? "tab--active" : ""}`}
            onClick={() => setActive("calibrate")}
          >
            校准与状态
          </button>
          <button
            className={`tab ${active === "report" ? "tab--active" : ""}`}
            onClick={() => setActive("report")}
          >
            规则报表
          </button>
        </nav>
      </div>

      {/* 主体内容 */}
      <main className="container">
        {/* 17 总览仪表盘 */}
        {active === "overview" && (
          <section className="grid grid--1">
            <div className="card">
              <Dashboard apiBase={apiBase} />
            </div>
          </section>
        )}

        {/* 5 工作台（含 8 高亮） */}
        {active === "triage" && (
          <section className="grid grid--1">
            <div className="card">
              <AlertTriage apiBase={apiBase} />
            </div>
          </section>
        )}

        {/* 实时预测（左输入 / 右结果；结果下可挂资产/流量） */}
        {active === "predict" && (
          <>
            <section className="grid grid--2">
              <div className="card card--stretch">
                <div className="card__title">单条日志 JSON</div>
                <textarea
                  value={singleJson}
                  onChange={(e) => setSingleJson(e.target.value)}
                  spellCheck={false}
                  className="textarea"
                />
                <div className="row gap-8 mt-8">
                  <button
                    onClick={doPredict}
                    disabled={singleLoading}
                    className="btn btn--primary"
                  >
                    {singleLoading ? "预测中..." : "预测"}
                  </button>
                  <button
                    onClick={() => { setSingleRes(null); setSingleErr(""); }}
                    className="btn"
                  >
                    清空结果
                  </button>
                </div>
                {singleErr && <div className="error mt-8">错误：{singleErr}</div>}
              </div>

              <div className="card card--stretch">
                <div className="card__title">预测结果</div>
                {!singleRes ? (
                  <div className="muted">暂无</div>
                ) : (
                  <div className="kv">
                    <div className="kv__row">
                      <div className="kv__key">标签</div>
                      <div className="kv__val">
                        <b className={singleRes.label === "攻击" ? "text-danger" : "text-ok"}>
                          {singleRes.label}
                        </b>
                      </div>
                    </div>
                    <div className="kv__row">
                      <div className="kv__key">score_raw</div>
                      <div className="kv__val">{fmt(singleRes.score_raw)}</div>
                    </div>
                    <div className="kv__row">
                      <div className="kv__key">score_final</div>
                      <div className="kv__val"><b>{fmt(singleRes.score_final)}</b></div>
                    </div>
                    <div className="kv__row">
                      <div className="kv__key">当前阈值</div>
                      <div className="kv__val">{fmt(singleRes.threshold, 6)}</div>
                    </div>

                    {singleRes.top_terms?.length ? (
                      <div className="chips">
                        {singleRes.top_terms.map((t, i) => (
                          <span key={i} className="chip">{t}</span>
                        ))}
                      </div>
                    ) : null}

                    {singleRes.rules?.length ? (
                      <div className="chips">
                        {singleRes.rules.map((r, i) => (
                          <span key={i} className="chip chip--warn">{r}</span>
                        ))}
                      </div>
                    ) : null}
                  </div>
                )}
              </div>
            </section>

            {/* 资产与流量（12 & 14）：如果有 id/asset_id，就展示关联信息 */}
            {(singleRes?.id || singleRes?.asset_id) && (
              <section className="grid grid--1">
                <div className="card">
                  <AssetFlowPanel
                    apiBase={apiBase}
                    alertId={singleRes?.id}
                    assetId={singleRes?.asset_id ?? undefined}
                  />
                </div>
              </section>
            )}
          </>
        )}

        {/* 批量评估 */}
        {active === "batch" && (
          <section className="grid grid--1">
            <div className="card">
              <BatchEvalPanel apiBase={apiBase} />
            </div>
          </section>
        )}

        {/* 校准与状态 */}
        {active === "calibrate" && (
          <section className="grid grid--2">
            <div className="card card--stretch">
              <CalibratePanel apiBase={apiBase} />
            </div>
            <div className="card card--stretch">
              <MetaPanel apiBase={apiBase} />
            </div>
          </section>
        )}

        {/* 规则报表 */}
        {active === "report" && (
          <section className="grid grid--1">
            <div className="card">
              <RulesReport apiBase={apiBase} />
            </div>
          </section>
        )}
      </main>

      <footer className="footer">
        <div>© 2025 WAF/IDS 智能告警控制台 · A1LinLin1</div>
      </footer>
    </div>
  );
}
