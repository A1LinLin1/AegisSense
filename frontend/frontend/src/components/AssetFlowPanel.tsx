import React, { useEffect, useMemo, useState } from "react";

export default function AssetFlowPanel({ apiBase, alertId, assetId }:{ apiBase:string; alertId?:number; assetId?:number }) {
  const base = useMemo(()=>apiBase.replace(/\/+$/,""),[apiBase]);
  const [asset, setAsset] = useState<any>(null);
  const [flows, setFlows] = useState<any>(null);

  useEffect(()=>{ (async()=>{
    if (assetId!=null) {
      const r = await fetch(`${base}/assets/${assetId}`); setAsset(await r.json());
    }
  })(); }, [base, assetId]);

  useEffect(()=>{ (async()=>{
    if (alertId!=null) {
      const r = await fetch(`${base}/flows/by_alert/${alertId}`); setFlows(await r.json());
    }
  })(); }, [base, alertId]);

  return (
    <div className="grid grid--2">
      <div className="card">
        <div className="card__title">资产画像</div>
        {!asset ? <div className="muted">无</div> : (
          <div className="kv">
            <div className="kv__row"><div className="kv__key">名称</div><div className="kv__val">{asset.name}</div></div>
            <div className="kv__row"><div className="kv__key">重要度</div><div className="kv__val">{asset.criticality}</div></div>
            <div className="kv__row"><div className="kv__key">外网暴露</div><div className="kv__val">{asset.internet_exposed ? "是" : "否"}</div></div>
            <div className="kv__row"><div className="kv__key">分区</div><div className="kv__val">{asset.segment}</div></div>
            <div className="kv__row"><div className="kv__key">补丁滞后</div><div className="kv__val">{asset.patch_delay_days} 天</div></div>
          </div>
        )}
      </div>
      <div className="card">
        <div className="card__title">关联流量/PCAP</div>
        {!flows ? <div className="muted">无</div> : (
          <table>
            <thead><tr><th>时间窗</th><th>五元组</th><th>字节</th><th>连接速率</th><th>PCAP</th></tr></thead>
            <tbody>
              {(flows.items||[]).map((f:any,i:number)=>(
                <tr key={i}>
                  <td>{f.start_ts} ~ {f.end_ts}</td>
                  <td>{f.src_ip}:{f.sport} → {f.dst_ip}:{f.dport}</td>
                  <td>in {f.bytes_in} / out {f.bytes_out}</td>
                  <td>{f.conn_rate}/min</td>
                  <td>{f.pcap_path ? <a href={f.pcap_path} target="_blank" rel="noreferrer">下载</a> : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
