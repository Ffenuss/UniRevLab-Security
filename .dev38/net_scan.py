import re

URL_RE = re.compile(r"\b(?:https?|wss?)://[^\s\"'<>\\]{4,512}", re.I)
CRYPTO_MARKERS = ("aes/gcm", "aes/cbc", "chacha20", "blowfish", "xtea", "pbkdf2", "hkdf")
KEY_MARKERS = ("encryption_key", "aes_key", "keystore", "keyalias", "secretkeyspec", "keygenerator", "api_key", "client_id")

def find_network_and_crypto_markers(text: str):
    rows=[]
    for m in URL_RE.finditer(text):
        rows.append({"kind":"endpoint","value":m.group(0),"offset":m.start()})
    low=text.lower()
    for marker in CRYPTO_MARKERS:
        pos=low.find(marker)
        if pos>=0:
            rows.append({"kind":"crypto-marker","marker":marker,"offset":pos})
    for marker in KEY_MARKERS:
        pos=low.find(marker)
        if pos>=0:
            rows.append({"kind":"key-marker","marker":marker,"offset":pos})
    return rows
