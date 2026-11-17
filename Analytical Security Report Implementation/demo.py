"""
demo.py - narrated live demo of hashing, symmetric and asymmetric methods.
Run for recording:  python demo.py          (press Enter to advance each step)
Run without pauses: python demo.py --auto
Each step prints the SECURITY SERVICE it demonstrates - say it out loud.
"""
import hashlib, os, sys, time
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

AUTO = "--auto" in sys.argv

def pause():
    if AUTO: time.sleep(0.2)
    else: input("   [Enter to continue] ")

def section(title):
    print("\n" + "=" * 70 + f"\n{title}\n" + "=" * 70)

def step(text, service=None):
    print(f"\n>> {text}")
    if service: print(f"   SECURITY SERVICE: {service}")

def hexp(b, n=16):
    return b[:n].hex() + ("..." if len(b) > n else "")

def bits_changed(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b)) / (len(a) * 8)

# ============================== 1. HASHING ==============================
section("1. HASHING - MD5, SHA-256, SHA3-256")
msg = b"Transfer $100 to Alice"
step("Digest of one message with each hash", "INTEGRITY (fixed-size fingerprint)")
for name, label in (("md5", "MD5     "), ("sha256", "SHA-256 "), ("sha3_256", "SHA3-256")):
    d = hashlib.new(name, msg).digest()
    print(f"   {label}  {len(d)*8:>3} bits  {d.hex()[:40]}...")
pause()

step("Avalanche effect: flip ONE input bit and compare digests", "INTEGRITY (any change is visible)")
flipped = bytearray(msg); flipped[0] ^= 1
for name, label in (("md5", "MD5     "), ("sha256", "SHA-256 "), ("sha3_256", "SHA3-256")):
    a, b = hashlib.new(name, msg).digest(), hashlib.new(name, bytes(flipped)).digest()
    print(f"   {label}  {bits_changed(a, b):.0%} of output bits changed")
pause()

step("File integrity check: change a single byte in a 1 MB file", "INTEGRITY (detects modification)")
f = os.urandom(1_000_000); f2 = bytearray(f); f2[500_000] ^= 1
h1, h2 = hashlib.sha256(f).hexdigest(), hashlib.sha256(bytes(f2)).hexdigest()
print(f"   original : {h1[:32]}...\n   modified : {h2[:32]}...\n   match? {h1 == h2}")
print("   NOTE: MD5 has known collisions (Wang & Yu 2005): do not use it for security.")
pause()

# ============================== 2. SYMMETRIC ==============================
section("2. SYMMETRIC - AES-GCM, ChaCha20, 3DES")
plain = b"Transfer $100 to Alice"
step("AES-256-GCM encrypt and decrypt", "CONFIDENTIALITY + INTEGRITY (authenticated encryption)")
key, nonce = AESGCM.generate_key(256), os.urandom(12)
ct = AESGCM(key).encrypt(nonce, plain, None)
print(f"   plaintext  : {plain}\n   ciphertext : {hexp(ct, 22)}  ({len(ct)} B = {len(plain)} + 16-byte tag)")
print(f"   decrypted  : {AESGCM(key).decrypt(nonce, ct, None)}")
pause()

step("ATTACK: attacker flips ciphertext bits to change $100 into $900 (no key needed)")
def attack(ct_bytes):
    b = bytearray(ct_bytes); b[10] ^= ord("1") ^ ord("9")     # byte 10 is the '1' of "$100"
    return bytes(b)

step("AES-GCM under attack", "INTEGRITY (tag check fails)")
try:
    AESGCM(key).decrypt(nonce, attack(ct), None); print("   accepted (BAD)")
except InvalidTag:
    print("   REJECTED: InvalidTag - tampering detected")
pause()

step("Raw ChaCha20 under the same attack", "CONFIDENTIALITY ONLY (no integrity)")
ck, cn = os.urandom(32), os.urandom(16)
cct = Cipher(algorithms.ChaCha20(ck, cn), mode=None).encryptor().update(plain)
bad = Cipher(algorithms.ChaCha20(ck, cn), mode=None).decryptor().update(attack(cct))
print(f"   receiver reads: {bad}   <- silently altered, no error")
print("   Fix: ChaCha20-Poly1305 adds the authentication tag.")
pause()

step("3DES-CBC (deprecated)", "CONFIDENTIALITY ONLY; weak 64-bit block")
k3, iv = DES3.adjust_key_parity(os.urandom(24)), os.urandom(8)
c3 = DES3.new(k3, DES3.MODE_CBC, iv).encrypt(pad(plain, 8))
print(f"   round trip OK: {unpad(DES3.new(k3, DES3.MODE_CBC, iv).decrypt(c3), 8) == plain}")
print("   NIST: disallowed after 2023. Sweet32 (Bhargavan & Leurent, 2016): 64-bit block collisions.")
pause()

# ============================== 3. ASYMMETRIC ==============================
section("3. ASYMMETRIC - RSA-2048, ECC P-256, Ed25519")
doc = b"Release v1.0 - official build"
pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

step("Ed25519: sign, verify, then verify a tampered document",
     "AUTHENTICATION + INTEGRITY + NON-REPUDIATION")
edk = ed25519.Ed25519PrivateKey.generate(); sig = edk.sign(doc)
edk.public_key().verify(sig, doc)
print(f"   signature ({len(sig)} bytes) VERIFIED with the public key")
try:
    edk.public_key().verify(sig, doc + b"!"); print("   accepted (BAD)")
except InvalidSignature:
    print("   tampered document REJECTED: InvalidSignature")
pause()

step("Compare RSA-2048 (PSS), ECDSA P-256 and Ed25519 signatures", "NON-REPUDIATION (size and speed trade-off)")
rk = rsa.generate_private_key(65537, 2048); ek = ec.generate_private_key(ec.SECP256R1())
for name, sign in (("RSA-2048 PSS", lambda: rk.sign(doc, pss, hashes.SHA256())),
                   ("ECDSA P-256 ", lambda: ek.sign(doc, ec.ECDSA(hashes.SHA256()))),
                   ("Ed25519     ", lambda: edk.sign(doc))):
    s = sign()                                    # warm-up call (excluded from timing)
    t0 = time.perf_counter()
    for _ in range(50): sign()
    dt = (time.perf_counter() - t0) * 1e3 / 50    # average of 50 runs
    print(f"   {name}  signature {len(s):>3} B   avg sign time {dt:.3f} ms")
pause()

step("RSA-OAEP: encrypt a small AES key (RSA cannot encrypt large files)", "KEY TRANSPORT / CONFIDENTIALITY")
aes_key = os.urandom(32); wrapped = rk.public_key().encrypt(aes_key, oaep)
print(f"   AES key (32 B) -> RSA ciphertext {len(wrapped)} B; recovered: {rk.decrypt(wrapped, oaep) == aes_key}")
pause()

step("Hybrid: ECDH (P-256) + HKDF -> AES-GCM", "KEY ESTABLISHMENT + CONFIDENTIALITY + INTEGRITY")
alice, bob = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
def derive(priv, pub):
    return HKDF(hashes.SHA256(), 32, None, b"demo").derive(priv.exchange(ec.ECDH(), pub))
ka, kb = derive(alice, bob.public_key()), derive(bob, alice.public_key())
print(f"   Alice and Bob derived the same key without sending it: {ka == kb}")
n = os.urandom(12); secret = b"Meet at 10am, room 4"
print(f"   Bob decrypts Alice's message: {AESGCM(kb).decrypt(n, AESGCM(ka).encrypt(n, secret, None), None)}")
pause()

section("SUMMARY")
print("   Hashes ......... integrity only (MD5 broken)")
print("   AES-GCM ........ confidentiality + integrity; raw ChaCha20 / 3DES: confidentiality only")
print("   RSA / ECC / Ed25519 ... signatures give authentication + non-repudiation; ECDH/RSA give key establishment")
print("   Real systems combine all three (hybrid encryption).\n")