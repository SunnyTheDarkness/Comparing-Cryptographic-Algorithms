"""
benchmark.py - times all 9 algorithms and saves CSV results.
Run full:   python benchmark.py
Quick test: python benchmark.py --quick
"""
import csv, hashlib, os, platform, sys, time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

QUICK = "--quick" in sys.argv
SIZES = [1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000]
REPS = 30            # repetitions per condition (hash / symmetric / hybrid)
ASYM_REPS = 100      # sign/verify take microseconds, so more reps are cheap 
KEYGEN_REPS = 30
WARMUP = 3
if QUICK:
    SIZES, REPS, ASYM_REPS, KEYGEN_REPS, WARMUP = SIZES[:5], 3, 5, 3, 1

OUT = Path("results"); OUT.mkdir(exist_ok=True)
now = time.perf_counter_ns

def timed(fn):
    t0 = now(); r = fn(); return (now() - t0) / 1e9, r      # seconds

def write_csv(name, header, rows):
    with open(OUT / name, "w", newline="") as f:
        w = csv.writer(f); w.writerow(header); w.writerows(rows)

def summarise(raw_name, sum_name, key_cols):
    import pandas as pd
    df = pd.read_csv(OUT / raw_name)
    g = df.groupby(key_cols)["time_s"].agg(["count", "mean", "std", "median", "min", "max"])
    g = g.reset_index()
    if "size_bytes" in df.columns:
        g["throughput_MBps"] = g["size_bytes"] / 1e6 / g["mean"]
    g.to_csv(OUT / sum_name, index=False)

# ---------------- environment ----------------
with open(OUT / "env_info.txt", "w") as f:
    f.write(f"Python {sys.version}\nOS {platform.platform()}\n"
            f"CPU {platform.processor()}\nCores {os.cpu_count()}\n")
    try:
        import psutil
        f.write(f"RAM_GB {psutil.virtual_memory().total/1e9:.1f}\n")
    except Exception: pass
print("Mode:", "QUICK" if QUICK else "FULL")

# ---------------- 1. HASHING ----------------
print("Hashing...")
rows = []
for size in SIZES:
    data = os.urandom(size)
    for algo in ("md5", "sha256", "sha3_256"):
        for _ in range(WARMUP): hashlib.new(algo, data).digest()
        for rep in range(REPS):
            t, d = timed(lambda: hashlib.new(algo, data).digest())
            rows.append([algo, size, rep, t, len(d)])
write_csv("hash_raw.csv", ["algorithm", "size_bytes", "rep", "time_s", "digest_bytes"], rows)
summarise("hash_raw.csv", "hash_summary.csv", ["algorithm", "size_bytes"])

# ---------------- 2. SYMMETRIC ----------------
print("Symmetric...")
rows = []
def aes_gcm(data):
    a = AESGCM(AESGCM.generate_key(256))
    def run():
        n = os.urandom(12)                           # fresh nonce every call
        te, ct = timed(lambda: a.encrypt(n, data, None))
        td, pt = timed(lambda: a.decrypt(n, ct, None))
        assert pt == data
        return te, td, len(ct) - len(data)
    return run
def chacha_aead(data):
    c = ChaCha20Poly1305(ChaCha20Poly1305.generate_key())
    def run():
        n = os.urandom(12)
        te, ct = timed(lambda: c.encrypt(n, data, None))
        td, pt = timed(lambda: c.decrypt(n, ct, None))
        assert pt == data
        return te, td, len(ct) - len(data)
    return run
def chacha_raw(data):
    key = os.urandom(32)
    def run():
        n = os.urandom(16)
        te, ct = timed(lambda: Cipher(algorithms.ChaCha20(key, n), mode=None).encryptor().update(data))
        td, pt = timed(lambda: Cipher(algorithms.ChaCha20(key, n), mode=None).decryptor().update(ct))
        assert pt == data
        return te, td, len(ct) - len(data)
    return run
def des3_cbc(data):
    key = DES3.adjust_key_parity(os.urandom(24)); padded = pad(data, 8)  # padding excluded from timing
    def run():
        iv = os.urandom(8)
        te, ct = timed(lambda: DES3.new(key, DES3.MODE_CBC, iv).encrypt(padded))
        td, pt = timed(lambda: DES3.new(key, DES3.MODE_CBC, iv).decrypt(ct))
        assert unpad(pt, 8) == data
        return te, td, len(ct) - len(data) + 8       # +8 = IV sent alongside
    return run

SYM = {"AES-256-GCM": aes_gcm, "ChaCha20 (raw)": chacha_raw,
       "ChaCha20-Poly1305": chacha_aead, "3DES-CBC": des3_cbc}
for size in SIZES:
    data = os.urandom(size)
    for name, builder in SYM.items():
        run = builder(data)
        for _ in range(WARMUP): run()
        for rep in range(REPS):
            te, td, ov = run()
            rows.append([name, size, rep, "encrypt", te, ov])
            rows.append([name, size, rep, "decrypt", td, ov])
    print(f"  {size:>11,} bytes done")
write_csv("symmetric_raw.csv",
          ["algorithm", "size_bytes", "rep", "operation", "time_s", "overhead_bytes"], rows)
summarise("symmetric_raw.csv", "symmetric_summary.csv", ["algorithm", "size_bytes", "operation"])

# ---------------- 3. ASYMMETRIC ----------------
print("Asymmetric...")
rows, sizes_rows = [], []
MSG = os.urandom(1024)
pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
DER = dict(encoding=serialization.Encoding.DER)

SCHEMES = {
    "RSA-2048 (PSS)": dict(
        gen=lambda: rsa.generate_private_key(65537, 2048),
        sign=lambda k: k.sign(MSG, pss, hashes.SHA256()),
        verify=lambda k, s: k.public_key().verify(s, MSG, pss, hashes.SHA256())),
    "ECDSA P-256": dict(
        gen=lambda: ec.generate_private_key(ec.SECP256R1()),
        sign=lambda k: k.sign(MSG, ec.ECDSA(hashes.SHA256())),
        verify=lambda k, s: k.public_key().verify(s, MSG, ec.ECDSA(hashes.SHA256()))),
    "Ed25519": dict(
        gen=lambda: ed25519.Ed25519PrivateKey.generate(),
        sign=lambda k: k.sign(MSG),
        verify=lambda k, s: k.public_key().verify(s, MSG)),
}
for name, s in SCHEMES.items():
    for rep in range(KEYGEN_REPS):
        t, _ = timed(s["gen"]); rows.append([name, "keygen", rep, t])
    key = s["gen"](); sig = s["sign"](key)
    for _ in range(WARMUP): s["sign"](key); s["verify"](key, sig)
    for rep in range(ASYM_REPS):
        t, sig = timed(lambda: s["sign"](key)); rows.append([name, "sign", rep, t])
    for rep in range(ASYM_REPS):
        t, _ = timed(lambda: s["verify"](key, sig)); rows.append([name, "verify", rep, t])
    priv = key.private_bytes(**DER, format=serialization.PrivateFormat.PKCS8,
                             encryption_algorithm=serialization.NoEncryption())
    pub = key.public_key().public_bytes(**DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    sizes_rows.append([name, len(priv), len(pub), len(sig)])

rk = rsa.generate_private_key(65537, 2048); small = os.urandom(32)   # RSA-OAEP, 32 B payload
for _ in range(WARMUP): rk.decrypt(rk.public_key().encrypt(small, oaep), oaep)
for rep in range(ASYM_REPS):
    t, ct = timed(lambda: rk.public_key().encrypt(small, oaep)); rows.append(["RSA-2048 (OAEP)", "encrypt_32B", rep, t])
for rep in range(ASYM_REPS):
    t, _ = timed(lambda: rk.decrypt(ct, oaep)); rows.append(["RSA-2048 (OAEP)", "decrypt_32B", rep, t])

ea, eb = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
for rep in range(ASYM_REPS):
    t, _ = timed(lambda: ea.exchange(ec.ECDH(), eb.public_key())); rows.append(["ECDH P-256", "key_agreement", rep, t])

write_csv("asymmetric_raw.csv", ["algorithm", "operation", "rep", "time_s"], rows)
write_csv("asymmetric_sizes.csv",
          ["algorithm", "private_key_der_bytes", "public_key_der_bytes", "signature_bytes"], sizes_rows)
summarise("asymmetric_raw.csv", "asymmetric_summary.csv", ["algorithm", "operation"])

# ---------------- 4. HYBRID PIPELINES ----------------
print("Hybrid pipelines...")
rows = []
HSIZES = [s for s in (1_000, 1_000_000, 10_000_000) if s in SIZES]
rsa_r = rsa.generate_private_key(65537, 2048)           # recipient keys made outside timing
ec_r = ec.generate_private_key(ec.SECP256R1())
def ecdh_pipeline(data):
    eph = ec.generate_private_key(ec.SECP256R1())
    k = HKDF(hashes.SHA256(), 32, None, b"hybrid").derive(eph.exchange(ec.ECDH(), ec_r.public_key()))
    n = os.urandom(12); ct = AESGCM(k).encrypt(n, data, None)
    k2 = HKDF(hashes.SHA256(), 32, None, b"hybrid").derive(ec_r.exchange(ec.ECDH(), eph.public_key()))
    assert AESGCM(k2).decrypt(n, ct, None) == data
    return len(ct) - len(data) + 65 + 12                 # +65 B ephemeral public key, +12 B nonce
def rsa_pipeline(data):
    k = AESGCM.generate_key(256)
    wrapped = rsa_r.public_key().encrypt(k, oaep)
    n = os.urandom(12); ct = AESGCM(k).encrypt(n, data, None)
    k2 = rsa_r.decrypt(wrapped, oaep)
    assert AESGCM(k2).decrypt(n, ct, None) == data
    return len(ct) - len(data) + len(wrapped) + 12
for size in HSIZES:
    data = os.urandom(size)
    for name, fn in (("ECDH P-256 + HKDF + AES-GCM", ecdh_pipeline),
                     ("RSA-OAEP + AES-GCM", rsa_pipeline)):
        for _ in range(WARMUP): fn(data)
        for rep in range(REPS):
            t, ov = timed(lambda: fn(data)); rows.append([name, size, rep, t, ov])
write_csv("hybrid_raw.csv", ["pipeline", "size_bytes", "rep", "time_s", "overhead_bytes"], rows)
summarise("hybrid_raw.csv", "hybrid_summary.csv", ["pipeline", "size_bytes"])

print("\nDone. CSV files are in:", OUT.resolve())