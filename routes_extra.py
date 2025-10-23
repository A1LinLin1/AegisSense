# routes_extra.py
from fastapi import APIRouter, HTTPException, Query
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

router = APIRouter()

# ============= 5) 告警工作台：列表/详情/打标签 =============
@router.post("/alerts/search")
def search_alerts(body: Dict[str, Any]):
    """
    body: {query?: {...}, page?:1, size?:50, sort?:"-ts"}
    先返回模拟数据；接库后替换成真实查询
    """
    page = int(body.get("page", 1))
    size = int(body.get("size", 50))
    items = [{
        "id": 123,
        "ts": datetime.utcnow().isoformat(timespec="seconds"),
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.9",
        "uri": "/admin/login?u=1", "method": "GET",
        "ua": "sqlmap/1.7", "rsp_status": 403,
        "label_pred": "攻击", "model_score": 0.96, "rule_hits": ["rule:scanner_ua"],
        "asset_id": 1,
    }]
    total = 1
    return {"total": total, "items": items, "page": page, "size": size}

@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: int):
    return {
        "id": alert_id,
        "ts": datetime.utcnow().isoformat(timespec="seconds"),
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.9",
        "uri": "/search?q=%27+UNION+SELECT+1--",
        "method": "GET", "ua": "Mozilla/5.0",
        "payload": {
            "headers": {"User-Agent": "Mozilla/5.0", "X-Token": "abc"},
            "query": "q=%27+UNION+SELECT+1--",
            "body": ""
        },
        "rule_hits": ["rule:resp_whitelist", "kw:union select"],
        "model_score": 0.91, "fused_score": 0.88, "label_pred": "攻击",
        "asset_id": 1,
    }

@router.post("/alerts/{alert_id}/label")
def label_alert(alert_id: int, body: Dict[str, Any]):
    """
    body: {human_label:'攻击'|'误报', comment?:string, created_by?:string}
    TODO: 写 feedback 表；这里先返回 ok
    """
    if body.get("human_label") not in ("攻击", "误报"):
        raise HTTPException(400, "invalid human_label")
    return {"ok": True}

# ============= 8) 规则命中解释（高亮） =============
@router.post("/explain")
def explain(body: Dict[str, Any]):
    """
    body: {text_parts: {uri, headers?, body?, query?}, top_terms?:string[]}
    返回用于前端高亮的区间
    """
    text_parts = body.get("text_parts", {}) or {}
    top_terms = body.get("top_terms", ["union", "select", "1=1"])
    highlights: List[Dict[str, Any]] = []
    for key in ("uri", "query", "body"):
        s = (text_parts.get(key) or "")
        s_low = s.lower()
        for term in top_terms:
            t = term.lower()
            i = s_low.find(t)
            if i >= 0:
                highlights.append({"field": key, "start": i, "end": i+len(term), "term": term})
    return {"highlights": highlights}

# ============= 10) 规则贡献度报表 =============
@router.get("/rules/report")
def rules_report(range: str = Query("7d")):
    data = [
        {"rule_name":"rule:scanner_ua", "hits": 530, "reduced": 410, "suspected_miss": 2, "trend":[80,70,60,90,110,70,50]},
        {"rule_name":"rule:resp_whitelist", "hits": 210, "reduced": 205, "suspected_miss": 0, "trend":[20,30,40,30,40,25,25]},
    ]
    return {"range": range, "items": data}

# ============= 12) 资产/CMDB 画像 =============
@router.get("/assets/{asset_id}")
def get_asset(asset_id: int):
    return {
        "id": asset_id, "name": "payment-gateway",
        "criticality": 5, "internet_exposed": True, "segment": "DMZ",
        "patch_delay_days": 45
    }

# ============= 14) 流量/PCAP 关联 =============
@router.get("/flows/by_alert/{alert_id}")
def flows_by_alert(alert_id: int):
    return {
        "alert_id": alert_id,
        "items": [
            {
              "id": 999,
              "start_ts": datetime.utcnow().isoformat(timespec="seconds"),
              "end_ts": (datetime.utcnow()+timedelta(seconds=60)).isoformat(timespec="seconds"),
              "src_ip": "10.0.0.1", "dst_ip": "10.0.0.9", "sport": 52123, "dport": 443,
              "bytes_in": 12000, "bytes_out": 520000, "conn_rate": 80,
              "pcap_path": "/pcaps/2025-10-23/alert-999.pcap"
            }
        ]
    }

# ============= 17) 总览仪表盘 =============
@router.get("/overview")
def overview():
    return {
        "today": {"total": 12450, "attack_rate": 0.37, "blocked_rate": 0.92},
        "trend_24h": [320,510,600,800,1200,900,650,400,350,600,900,1200,1100,900,700,650,620,590,560,540,500,480,460,430],
        "top_uri": [{"uri":"/search","count":2300},{"uri":"/admin","count":1200},{"uri":"/phpmyadmin","count":950}],
        "top_ua": [{"ua":"sqlmap/1.x","count":540},{"ua":"curl/7.x","count":430},{"ua":"Mozilla/5.0","count":1200}],
        "geo_heat": [{"country":"CN","count":5300},{"country":"US","count":2400},{"country":"RU","count":900}],
        "kpi": {"tp": 310, "fp": 55, "tn": 11800, "fn": 10}
    }
