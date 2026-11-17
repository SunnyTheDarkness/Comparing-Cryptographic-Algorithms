"""
analyse.py (v2) - HD-oriented figures and tables from ./results.
Run: python analyse.py
Output: ./figures/*.png, key_results.csv, captions.txt
All time plots use MEDIAN with the inter-quartile range (IQR, 25th-75th
percentile). Means and SDs are kept in key_results.csv.
"""
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

R, F = Path("results"), Path("figures")
F.mkdir(exist_ok=True)
plt.rcParams.update({"figure.dpi": 120, "savefig.dpi": 300, "font.size": 10,
                     "axes.grid": True, "grid.alpha": 0.3,
                     "axes.spines.top": False, "axes.spines.right": False})

def save(fig, name):
    fig.tight_layout(); fig.savefig(F / name); plt.close(fig); print("saved", name)

def size_label(b):
    return f"{b/1e6:g} MB" if b >= 1e6 else f"{b/1e3:g} KB"

def fmt_time(s):                       # seconds -> readable string
    return f"{s*1e3:.2f} ms" if s >= 1e-3 else f"{s*1e6:.1f} us"

def summarise(df, keys):
    g = df.groupby(keys)["time_s"]
    out = g.agg(median="median", mean="mean", std="std", n="count",
                q1=lambda s: s.quantile(.25), q3=lambda s: s.quantile(.75))
    return out.reset_index()

hash_raw = pd.read_csv(R / "hash_raw.csv")
sym_raw = pd.read_csv(R / "symmetric_raw.csv")
asym_raw = pd.read_csv(R / "asymmetric_raw.csv")
hyb_raw = pd.read_csv(R / "hybrid_raw.csv")
sizes_df = pd.read_csv(R / "asymmetric_sizes.csv")

H = summarise(hash_raw, ["algorithm", "size_bytes"])
S = summarise(sym_raw, ["algorithm", "size_bytes", "operation"])
A = summarise(asym_raw, ["algorithm", "operation"])
Y = summarise(hyb_raw, ["pipeline", "size_bytes"])
for d in (H, S):                       # throughput (MB/s) from median time; band from IQR
    d["tp"] = d["size_bytes"] / 1e6 / d["median"]
    d["tp_lo"] = d["size_bytes"] / 1e6 / d["q3"]
    d["tp_hi"] = d["size_bytes"] / 1e6 / d["q1"]
N_HASH = int(H["n"].min()); N_SYM = int(S["n"].min())
N_ASYM = int(A[A["operation"].isin(["sign", "verify"])]["n"].min())
N_KEYGEN = int(A[A["operation"] == "keygen"]["n"].min())
caps = []

# ---------- Figure 0: security-services matrix (context for the report) ----------
services = ["Confidentiality", "Integrity", "Authentication", "Non-repudiation", "Key establishment"]
M = {  # 2 = provides, 1 = limited / conditional, 0 = not provided
    "MD5":               [0, 1, 0, 0, 0],
    "SHA-256":           [0, 2, 0, 0, 0],
    "SHA3-256":          [0, 2, 0, 0, 0],
    "AES-GCM":           [2, 2, 1, 0, 0],
    "ChaCha20 (raw)":    [2, 0, 0, 0, 0],
    "3DES-CBC":          [1, 0, 0, 0, 0],
    "RSA-2048":          [1, 2, 2, 2, 2],
    "ECC P-256":         [1, 2, 2, 2, 2],
    "Ed25519":           [0, 2, 2, 2, 0],
}
colour = {2: "#7fc97f", 1: "#fdd47a", 0: "#e6e6e6"}
text = {2: "Yes", 1: "Limited", 0: "-"}
fig, ax = plt.subplots(figsize=(8.5, 4.6))
for r, (alg, row) in enumerate(M.items()):
    for c, v in enumerate(row):
        ax.add_patch(plt.Rectangle((c, -r - 1), 1, 1, fc=colour[v], ec="white", lw=2))
        ax.text(c + .5, -r - .5, text[v], ha="center", va="center", fontsize=9)
ax.set_xlim(0, len(services)); ax.set_ylim(-len(M), 0)
ax.set_xticks([i + .5 for i in range(len(services))]); ax.set_xticklabels(services, rotation=20, ha="left")
ax.set_yticks([-i - .5 for i in range(len(M))]); ax.set_yticklabels(list(M))
ax.xaxis.tick_top(); ax.grid(False)
for s in ax.spines.values(): s.set_visible(False)
ax.set_title("Security services provided by each algorithm", pad=40)
save(fig, "fig0_security_services.png")
caps.append("Fig. 0: Security services provided by the nine algorithms. 'Limited' = conditional: MD5 "
            "(collision-broken, non-security checksums only), 3DES (deprecated), RSA/ECC encryption "
            "(small payloads or via hybrid ECDH only), AES-GCM authentication (shared key, so no non-repudiation).")

# ---------- Figure 1: hash throughput ----------
HL = {"md5": "MD5 (broken: collisions)", "sha256": "SHA-256 (SHA-2)", "sha3_256": "SHA3-256 (Keccak)"}
HC = {"md5": "#d62728", "sha256": "#1f77b4", "sha3_256": "#2ca02c"}
fig, ax = plt.subplots(figsize=(6.5, 4.2))
for a, g in H.groupby("algorithm"):
    ax.plot(g["size_bytes"], g["tp"], marker="o", color=HC[a], label=HL[a])
    ax.fill_between(g["size_bytes"], g["tp_lo"], g["tp_hi"], color=HC[a], alpha=.2)
ax.set_xscale("log"); ax.set_xlabel("Input size (bytes, log scale)")
ax.set_ylabel("Throughput (MB/s)"); ax.set_title("Hash throughput vs input size")
ax.legend(); save(fig, "fig1_hash_throughput.png")
caps.append(f"Fig. 1: Hash throughput vs input size. Lines show median throughput; shaded bands show the "
            f"IQR (25th-75th percentile) over n = {N_HASH} repetitions per point.")

# ---------- Figure 2: symmetric throughput ----------
SL = {"AES-256-GCM": ("AES-256-GCM (AEAD: confidentiality + integrity)", "#1f77b4", "-"),
      "ChaCha20-Poly1305": ("ChaCha20-Poly1305 (AEAD)", "#2ca02c", "-"),
      "ChaCha20 (raw)": ("ChaCha20 raw (no integrity)", "#2ca02c", "--"),
      "3DES-CBC": ("3DES-CBC (deprecated, no integrity)", "#d62728", "--")}
fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.4), sharey=True)
for ax, op in zip(axes, ("encrypt", "decrypt")):
    for a, g in S[S["operation"] == op].groupby("algorithm"):
        lab, col, ls = SL[a]
        ax.plot(g["size_bytes"], g["tp"], marker="o", color=col, ls=ls, label=lab)
        ax.fill_between(g["size_bytes"], g["tp_lo"], g["tp_hi"], color=col, alpha=.15)
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("Input size (bytes, log scale)"); ax.set_title(op.capitalize())
axes[0].set_ylabel("Throughput (MB/s, log scale)"); axes[0].legend(fontsize=8, loc="center right")
fig.suptitle("Symmetric cipher throughput vs input size (solid = authenticated, dashed = unauthenticated)")
save(fig, "fig2_symmetric_throughput.png")
caps.append(f"Fig. 2: Symmetric throughput vs input size. Median with IQR bands, n = {N_SYM} per point. "
            "Solid lines are authenticated (AEAD) modes; dashed lines provide confidentiality only.")

# ---------- Figure 3: asymmetric operations (median + IQR, value labels) ----------
schemes = ["RSA-2048 (PSS)", "ECDSA P-256", "Ed25519"]
sc_col = ["#1f77b4", "#ff7f0e", "#2ca02c"]
ops = ["keygen", "sign", "verify"]
fig, axes = plt.subplots(1, 3, figsize=(11, 4), sharey=True)
for ax, op in zip(axes, ops):
    sub = A[A["operation"] == op].set_index("algorithm").reindex(schemes)
    y = sub["median"] * 1e3
    err = [y - sub["q1"] * 1e3, sub["q3"] * 1e3 - y]
    ax.bar(range(3), y, color=sc_col, yerr=err, capsize=4)
    for i, v in enumerate(sub["median"]):
        ax.text(i, y.iloc[i] * 1.25, fmt_time(v), ha="center", fontsize=8)
    ax.set_xticks(range(3)); ax.set_xticklabels(["RSA-2048", "ECDSA\nP-256", "Ed25519"])
    ax.set_yscale("log"); ax.set_title(op)
axes[0].set_ylabel("Time (ms, log scale)")
fig.suptitle("Asymmetric operations: median time with IQR whiskers")
save(fig, "fig3_asymmetric_ops.png")
caps.append(f"Fig. 3: Asymmetric operation times (median, IQR whiskers). Sign and verify n = {N_ASYM}; "
            f"key generation n = {N_KEYGEN}. Key generation is right-skewed (RSA searches for random primes), "
            "so median and IQR are reported instead of mean and SD.")

# ---------- Figure 4: key and signature sizes ----------
fig, ax = plt.subplots(figsize=(7.5, 4.2))
w = .26
for i, (c, lab) in enumerate([("private_key_der_bytes", "Private key (DER)"),
                              ("public_key_der_bytes", "Public key (DER)"),
                              ("signature_bytes", "Signature")]):
    xs = [x + i * w for x in range(len(sizes_df))]
    ax.bar(xs, sizes_df[c], w, label=lab)
    for x, v in zip(xs, sizes_df[c]):
        ax.text(x, v * 1.1, f"{v}", ha="center", fontsize=8)
ax.set_xticks([x + w for x in range(len(sizes_df))]); ax.set_xticklabels(sizes_df["algorithm"])
ax.set_yscale("log"); ax.set_ylabel("Size (bytes, log scale)")
ax.set_title("Key and signature sizes"); ax.legend()
save(fig, "fig4_key_sizes.png")
caps.append("Fig. 4: Serialised key and signature sizes in bytes (private keys: PKCS#8 DER; public keys: "
            "SubjectPublicKeyInfo DER). Counts above bars are exact sizes.")

# ---------- Figure 5: hybrid pipelines (time + overhead) ----------
pipes = list(Y["pipeline"].unique()); sz = sorted(Y["size_bytes"].unique())
ov = hyb_raw.groupby(["pipeline", "size_bytes"])["overhead_bytes"].median().reset_index()
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2))
for i, p in enumerate(pipes):
    sub = Y[Y["pipeline"] == p].set_index("size_bytes").reindex(sz)
    y = sub["median"] * 1e3
    xs = [x + i * .38 for x in range(len(sz))]
    ax1.bar(xs, y, .38, yerr=[y - sub["q1"] * 1e3, sub["q3"] * 1e3 - y], capsize=3, label=p)
    for x, v in zip(xs, sub["median"]): ax1.text(x, v * 1e3 * 1.2, fmt_time(v), ha="center", fontsize=8)
    o = ov[ov["pipeline"] == p].set_index("size_bytes").reindex(sz)["overhead_bytes"]
    ax2.bar(xs, o, .38, label=p)
    for x, v in zip(xs, o): ax2.text(x, v + 2, f"{int(v)}", ha="center", fontsize=8)
for ax in (ax1, ax2):
    ax.set_xticks([x + .19 for x in range(len(sz))]); ax.set_xticklabels([size_label(s) for s in sz])
    ax.set_xlabel("Payload size")
ax1.set_yscale("log"); ax1.set_ylabel("End-to-end time (ms, log scale)")
ax1.set_title("Time (sender + recipient)"); ax1.legend(fontsize=8)
ax2.set_ylabel("Added bytes (overhead)"); ax2.set_title("Ciphertext overhead")
fig.suptitle("Hybrid encryption: ECDH key agreement vs RSA-OAEP key transport")
save(fig, "fig5_hybrid.png")
caps.append(f"Fig. 5: Hybrid pipelines (key establishment + AES-256-GCM). Left: median end-to-end time "
            f"(sender and recipient), IQR whiskers, n = {int(Y['n'].min())}. Right: bytes added to the payload "
            "(wrapped key or ephemeral public key, nonce, GCM tag).")

# ---------- Figure 6: security strength vs throughput ----------
# Strengths (bits): NIST SP 800-57 Pt 1 Rev 5 Table 2 / FIPS 202 / RFC 8439.
# Hash = collision strength; ciphers = key-search strength. MD5 plotted at its
# nominal 64-bit collision bound but is practically broken (hollow marker).
bigH, bigS = H["size_bytes"].max(), S["size_bytes"].max()
pts = [("MD5", H[(H.algorithm == "md5") & (H.size_bytes == bigH)]["tp"].iloc[0], 64, "broken", "s"),
       ("SHA-256", H[(H.algorithm == "sha256") & (H.size_bytes == bigH)]["tp"].iloc[0], 128, "ok", "s"),
       ("SHA3-256", H[(H.algorithm == "sha3_256") & (H.size_bytes == bigH)]["tp"].iloc[0], 128, "ok", "s")]
for a, lab, bits, st in (("AES-256-GCM", "AES-256-GCM", 256, "ok"),
                         ("ChaCha20-Poly1305", "ChaCha20-Poly1305", 256, "ok"),
                         ("3DES-CBC", "3DES-CBC", 112, "deprecated")):
    tp = S[(S.algorithm == a) & (S.operation == "encrypt") & (S.size_bytes == bigS)]["tp"].iloc[0]
    pts.append((lab, tp, bits, st, "o"))
sc = {"ok": ("#2ca02c", "Current / recommended"),
      "deprecated": ("#ff7f0e", "Deprecated (3DES disallowed by NIST after 2023)"),
      "broken": ("#d62728", "Broken for collision resistance")}
fig, ax = plt.subplots(figsize=(7.5, 4.6)); seen = set()
for lab, tp, bits, st, mk in pts:
    col, legend = sc[st]
    ax.scatter(tp, bits, s=110, marker=mk, color=col if st != "broken" else "white",
               edgecolor=col, linewidth=2, label=legend if st not in seen else None, zorder=3)
    off, ha = {"AES-256-GCM": ((8, -14), "left"), "ChaCha20-Poly1305": ((-8, 8), "right")}.get(lab, ((8, 6), "left"))
    seen.add(st); ax.annotate(lab, (tp, bits), textcoords="offset points", xytext=off, ha=ha, fontsize=8)
ax.set_xscale("log"); ax.set_xlim(right=max(p[1] for p in pts) * 3)
ax.set_xlabel(f"Throughput at {size_label(bigS)} (MB/s, log scale)")
ax.set_ylabel("Nominal security strength (bits)"); ax.set_ylim(0, 300)
ax.set_title("Security strength vs performance (squares = hashes, circles = ciphers)")
ax.legend(fontsize=8, loc="lower right"); save(fig, "fig6_security_vs_performance.png")
caps.append("Fig. 6: Nominal security strength against measured throughput. Strengths from NIST SP 800-57 Pt 1 "
            "Rev. 5 (3TDEA 112 bits, AES-256 256 bits, SHA-256 and SHA3-256 128-bit collision strength) and "
            "RFC 8439 (ChaCha20). MD5 is shown at its nominal 64-bit collision bound but is practically broken.")

# ---------- Table: key results ----------
rows = []
for _, r in H[H.size_bytes == bigH].iterrows():
    rows.append(["hash", r.algorithm, "digest", bigH, r["n"], r["median"], r.q1, r.q3, r["mean"], r["std"], r["tp"]])
for _, r in S[S.size_bytes == bigS].iterrows():
    rows.append(["symmetric", r.algorithm, r.operation, bigS, r["n"], r["median"], r.q1, r.q3, r["mean"], r["std"], r["tp"]])
for _, r in A.iterrows():
    rows.append(["asymmetric", r.algorithm, r.operation, None, r["n"], r["median"], r.q1, r.q3, r["mean"], r["std"], None])
pd.DataFrame(rows, columns=["group", "algorithm", "operation", "size_bytes", "n", "median_s",
                            "q1_s", "q3_s", "mean_s", "sd_s", "throughput_MBps"]).to_csv(F / "key_results.csv", index=False)
(F / "captions.txt").write_text("\n\n".join(caps), encoding="utf-8")
print("saved key_results.csv and captions.txt")
print("\nDone. Figures are in:", F.resolve())