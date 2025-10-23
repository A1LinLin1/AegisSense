import React, { useEffect, useMemo, useState } from "react";

function Highlighter({ text, highlights }: { text: string; highlights: any[] }) {
  if (!text) return <span className="muted">-</span>;
  const parts: any[] = [];
  let i = 0;
  const hs = (highlights||[]).sort((a,b)=>a.start-b.start);
  for (const h of hs) {
    if (h.start > i) parts.push(<span key={i}>{text.slice(i, h.start)}</span>);
    parts.push(<mark key={`${h.start}-${h.end}`}>{text.slice(h.start, h.end)}</mark>);
    i = h.end;
  }
  if (i < text.length) parts.push(<span key={i}>{text.slice(i)}</span>);
  return <span>{parts}</span>;
}

export default function AlertTriage({ apiBase }: { apiBase: string }) {
  const base = useMemo(() => apiBase.replace(/\/+$/, ""), [apiBase]);
  const searchUrl = `${base}/alerts/search`;
  const [list, setList] = useState<any[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [sel, setSel] = useState<any>(null);
  const [err, setErr] = useState("");

  const fetchList = async () => {
    try {
      const r = await fetch(searchUrl, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ page:1, size:50 }) });
      const d = await r.json();
      setList(d.items||[]); setTotal(d.total||0);
      setSel(null);
    } catch (e:any) { setErr(String(e?.message||e)); }
  };

  const fetchDetail = async (id:number) => {
    const r = await fetch(`${base}/alerts/${id}`);
    const d = await r.json();
    // 调用 explain 做高亮
    const text_parts = {
      uri: d.uri,
      query: d.payload?.query || "",
      body: d.payload?.body || ""
    };
    const ex = await fetch(`${base}/explain`, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ text_parts }) }).then(r=>r.json());
    setSel({ ...d, explain: ex });
  };

  useEffect(()=>{ fetchList(); /* eslint-disable-next-line */ }, [searchUrl]);

  return (
    <div className="grid grid--2">
      <div className="card">
        <div className="card__title">队列（{total}）</div>
        <table>
          <thead><tr><th>#</th><th>时间</th><th>来源</th><th>目标</th><th>URI</th><th>预测</th></tr></thead>
          <tbody>
            {list.map((x,i)=>(
              <tr key={i} onClick={()=>fetchDetail(x.id)} style={{ cursor:"pointer" }}>
                <td>{x.id}</td><td>{x.ts}</td><td>{x.src_ip}</td><td>{x.dst_ip}</td><td>{x.uri}</td>
                <td style={{ color: x.label_pred==="攻击"?"#dc2626":"#16a34a" }}>{x.label_pred}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {err && <div className="error mt-8">错误：{err}</div>}
      </div>
      <div className="card card--stretch">
        <div className="card__title">详情</div>
        {!sel ? <div className="muted">点击左侧一条查看详情</div> : (
          <div className="kv">
            <div className="kv__row"><div className="kv__key">URI</div><div className="kv__val">
              <Highlighter text={sel.uri} highlights={(sel.explain?.highlights||[]).filter((h:any)=>h.field==="uri")} />
            </div></div>
            <div className="kv__row"><div className="kv__key">Query</div><div className="kv__val">
              <Highlighter text={sel.payload?.query||""} highlights={(sel.explain?.highlights||[]).filter((h:any)=>h.field==="query")} />
            </div></div>
            <div className="kv__row"><div className="kv__key">Body</div><div className="kv__val">
              <Highlighter text={sel.payload?.body||""} highlights={(sel.explain?.highlights||[]).filter((h:any)=>h.field==="body")} />
            </div></div>
            <div className="chips">{(sel.rule_hits||[]).map((r:string,i:number)=><span className="chip chip--warn" key={i}>{r}</span>)}</div>
            <div className="note">预测：<b>{sel.label_pred}</b>　分数：{sel.fused_score ?? sel.model_score}</div>
          </div>
        )}
      </div>
    </div>
  );
}
