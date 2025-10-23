import React, { useEffect, useMemo, useState } from "react";

export default function RulesReport({ apiBase }: { apiBase: string }) {
  const [range, setRange] = useState("7d");
  const url = useMemo(() => `${apiBase.replace(/\/+$/, "")}/rules/report?range=${range}`, [apiBase, range]);
  const [data, setData] = useState<any>(null);

  useEffect(()=>{ (async()=>{
    const r = await fetch(url); setData(await r.json());
  })(); }, [url]);

  if (!data) return <div className="muted">加载中...</div>;

  return (
    <div className="card">
      <div className="row gap-8">
        <div className="card__title">规则贡献度（{range}）</div>
        <select className="input" style={{ width: 120 }} value={range} onChange={e=>setRange(e.target.value)}>
          <option value="7d">7 天</option>
          <option value="30d">30 天</option>
        </select>
      </div>
      <table>
        <thead><tr><th>规则</th><th>命中</th><th>减噪</th><th>疑似漏报</th><th>趋势</th></tr></thead>
        <tbody>
          {(data.items||[]).map((x:any,i:number)=>(
            <tr key={i}>
              <td>{x.rule_name}</td>
              <td>{x.hits}</td>
              <td>{x.reduced}</td>
              <td style={{ color: x.suspected_miss>0?"#dc2626":undefined }}>{x.suspected_miss}</td>
              <td className="muted">{(x.trend||[]).join(" / ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
