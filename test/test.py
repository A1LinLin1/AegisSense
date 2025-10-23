import requests, json
url = "http://127.0.0.1:8000/predict"
payload = {"alert":{
  "rsp_body": "{\"code\":500,\"message\":\"非法路径，该接口仅提供public目录下文件流获取\"}",
  "user-agent": "Mozilla/5.0",
  "confidence": "中", "hazard_rating": "低危",
  "uri": "/gateway/support/oss/getPublicInputStream?filePath=/etc/anacrontab",
  "rsp_status": "200"
}}
print(requests.post(url, json=payload).json())
