"""
tamper_test.py - flips one ciphertext bit and records whether decryption detects it.
Run: python tamper_test.py        Output: console table + results/tamper_results.csv
"""
import csv, os
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

TRIALS = 100
PLAIN = b"Transfer $100 to Alice"
FLIP = 10                                   # byte position of the flipped bit

def aes_gcm():
    k, n = AESGCM.generate_key(256), os.urandom(12)
    ct = bytearray(AESGCM(k).encrypt(n, PLAIN, None)); ct[FLIP] ^= 1
    try: AESGCM(k).decrypt(n, bytes(ct), None); return False, None
    except InvalidTag: return True, None

def chacha_poly():
    k, n = ChaCha20Poly1305.generate_key(), os.urandom(12)
    ct = bytearray(ChaCha20Poly1305(k).encrypt(n, PLAIN, None)); ct[FLIP] ^= 1
    try: ChaCha20Poly1305(k).decrypt(n, bytes(ct), None); return False, None
    except InvalidTag: return True, None

def chacha_raw():
    k, n = os.urandom(32), os.urandom(16)
    ct = bytearray(Cipher(algorithms.ChaCha20(k, n), mode=None).encryptor().update(PLAIN)); ct[FLIP] ^= 1
    out = Cipher(algorithms.ChaCha20(k, n), mode=None).decryptor().update(bytes(ct))
    return False, out                       # never raises an error

def des3_cbc():
    k, iv = DES3.adjust_key_parity(os.urandom(24)), os.urandom(8)
    ct = bytearray(DES3.new(k, DES3.MODE_CBC, iv).encrypt(pad(PLAIN, 8))); ct[FLIP] ^= 1
    try:
        out = unpad(DES3.new(k, DES3.MODE_CBC, iv).decrypt(bytes(ct)), 8)
        return False, out
    except ValueError:
        return True, None                   # only caught if padding happens to break

rows = []
for name, fn in (("AES-256-GCM", aes_gcm), ("ChaCha20-Poly1305", chacha_poly),
                 ("ChaCha20 (raw)", chacha_raw), ("3DES-CBC", des3_cbc)):
    detected, corrupted = 0, 0
    for _ in range(TRIALS):
        d, out = fn()
        detected += d
        corrupted += (out is not None and out != PLAIN)
    rows.append([name, TRIALS, detected, corrupted])
    print(f"{name:20s} detected {detected:>3}/{TRIALS}   accepted corrupted data {corrupted:>3}/{TRIALS}")

Path("results").mkdir(exist_ok=True)
with open("results/tamper_results.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["algorithm", "trials", "tamper_detected", "corrupted_plaintext_accepted"]); w.writerows(rows)
print("saved results/tamper_results.csv")