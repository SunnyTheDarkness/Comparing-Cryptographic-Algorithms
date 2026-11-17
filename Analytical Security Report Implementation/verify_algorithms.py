"""
verify_algorithms.py - Week 1 correctness checks for all 9 algorithms.
Install: pip install cryptography pycryptodome pandas matplotlib psutil
Run:     python verify_algorithms.py
"""
import hashlib, os, platform, sys

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import DES3          # PyCryptodome (3DES)
from Crypto.Util.Padding import pad, unpad

results = []
def check(name, ok):
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")

DATA = os.urandom(1024 * 1024)   # 1 MB test payload

# ---------------- ENVIRONMENT (copy into the Data Collection section) ----
print("Python:", sys.version.split()[0], "| OS:", platform.platform())
print("CPU:", platform.processor() or platform.machine())

# ---------------- HASHING -------------------------------------------------
# Known-answer tests (digest of b"abc")
check("MD5 known answer",
      hashlib.md5(b"abc").hexdigest() == "900150983cd24fb0d6963f7d28e17f72")
check("SHA-256 known answer",
      hashlib.sha256(b"abc").hexdigest() ==
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
check("SHA3-256 known answer",
      hashlib.sha3_256(b"abc").hexdigest() ==
      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")

for name in ("md5", "sha256", "sha3_256"):          # avalanche sanity check
    a = bytearray(b"hello world"); b = bytearray(a); b[0] ^= 1
    da = hashlib.new(name, a).digest(); db = hashlib.new(name, b).digest()
    diff = sum(bin(x ^ y).count("1") for x, y in zip(da, db)) / (len(da) * 8)
    check(f"{name} avalanche ~50% (got {diff:.0%})", 0.35 < diff < 0.65)

# ---------------- SYMMETRIC -----------------------------------------------
# AES-256-GCM (AEAD)
key, nonce = AESGCM.generate_key(256), os.urandom(12)
ct = AESGCM(key).encrypt(nonce, DATA, None)
check("AES-GCM round trip", AESGCM(key).decrypt(nonce, ct, None) == DATA)
tampered = bytearray(ct); tampered[10] ^= 1
try:
    AESGCM(key).decrypt(nonce, bytes(tampered), None); ok = False
except InvalidTag:
    ok = True
check("AES-GCM rejects tampered ciphertext", ok)

# ChaCha20 (raw stream cipher, NO authentication - this is intentional)
ckey, cnonce = os.urandom(32), os.urandom(16)       # 16 bytes = counter + nonce
enc = Cipher(algorithms.ChaCha20(ckey, cnonce), mode=None).encryptor()
cct = enc.update(DATA)
dec = Cipher(algorithms.ChaCha20(ckey, cnonce), mode=None).decryptor()
check("ChaCha20 round trip", dec.update(cct) == DATA)
bad = bytearray(cct); bad[10] ^= 1
dec = Cipher(algorithms.ChaCha20(ckey, cnonce), mode=None).decryptor()
silent = dec.update(bytes(bad)) != DATA            # decrypts without error
check("ChaCha20 silently accepts tampering (no integrity)", silent)

# 3DES-CBC via PyCryptodome (cryptography moved it to the decrepit module)
k3 = DES3.adjust_key_parity(os.urandom(24)); iv = os.urandom(8)
c3 = DES3.new(k3, DES3.MODE_CBC, iv).encrypt(pad(DATA, 8))
p3 = unpad(DES3.new(k3, DES3.MODE_CBC, iv).decrypt(c3), 8)
check("3DES-CBC round trip", p3 == DATA)

# ---------------- ASYMMETRIC ----------------------------------------------
MSG = b"message to sign"
# RSA-2048: PSS signature + OAEP encryption (small payload only)
rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
sig = rk.sign(MSG, pss, hashes.SHA256())
rk.public_key().verify(sig, MSG, pss, hashes.SHA256())
check("RSA-PSS sign/verify", True)
try:
    rk.public_key().verify(sig, MSG + b"x", pss, hashes.SHA256()); ok = False
except InvalidSignature:
    ok = True
check("RSA-PSS rejects modified message", ok)
oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
small = os.urandom(32)
check("RSA-OAEP round trip (32 B)",
      rk.decrypt(rk.public_key().encrypt(small, oaep), oaep) == small)

# ECDSA P-256
ek = ec.generate_private_key(ec.SECP256R1())
sig = ek.sign(MSG, ec.ECDSA(hashes.SHA256()))
ek.public_key().verify(sig, MSG, ec.ECDSA(hashes.SHA256()))
check("ECDSA P-256 sign/verify", True)
try:
    ek.public_key().verify(sig, MSG + b"x", ec.ECDSA(hashes.SHA256())); ok = False
except InvalidSignature:
    ok = True
check("ECDSA rejects modified message", ok)

# Ed25519
edk = ed25519.Ed25519PrivateKey.generate()
sig = edk.sign(MSG)
edk.public_key().verify(sig, MSG)
check("Ed25519 sign/verify", True)
try:
    edk.public_key().verify(sig, MSG + b"x"); ok = False
except InvalidSignature:
    ok = True
check("Ed25519 rejects modified message", ok)
check("Ed25519 is deterministic", edk.sign(MSG) == edk.sign(MSG))

# ---------------- HYBRID: ECDH (P-256) + HKDF + AES-GCM -------------------
alice = ec.generate_private_key(ec.SECP256R1())
bob = ec.generate_private_key(ec.SECP256R1())
def derive(priv, peer_pub):
    shared = priv.exchange(ec.ECDH(), peer_pub)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"hybrid-demo").derive(shared)
ka, kb = derive(alice, bob.public_key()), derive(bob, alice.public_key())
check("ECDH both sides derive same key", ka == kb)
n = os.urandom(12)
check("Hybrid ECDH+AES-GCM round trip",
      AESGCM(kb).decrypt(n, AESGCM(ka).encrypt(n, DATA, None), None) == DATA)

# ---------------- SUMMARY --------------------------------------------------
failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
sys.exit(1 if failed else 0)