"""
anova_figures.py - figures that support the ANOVA section.
Run AFTER benchmark.py and anova_analysis.py:  python anova_figures.py
Output: ./figures/fig7_anova_boxplots.png, fig8_interaction.png, fig9_qq_residuals.png
"""
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats

R, F = Path("results"), Path("figures"); F.mkdir(exist_ok=True)
plt.rcParams.update({"figure.dpi": 120, "savefig.dpi": 300, "font.size": 10,
                     "axes.grid": True, "grid.alpha": 0.3,
                     "axes.spines.top": False, "axes.spines.right": False})
hash_raw = pd.read_csv(R / "hash_raw.csv")
sym_raw = pd.read_csv(R / "symmetric_raw.csv")
asym_raw = pd.read_csv(R / "asymmetric_raw.csv")
an = pd.read_csv(R / "anova_oneway.csv").set_index("condition")

SYM = ["AES-256-GCM", "ChaCha20 (raw)", "3DES-CBC"]
ASYM = ["RSA-2048 (PSS)", "ECDSA P-256", "Ed25519"]
sym = sym_raw[sym_raw["algorithm"].isin(SYM)]
for d in (hash_raw, sym, asym_raw):
    d["y"] = np.log10(d["time_s"])

def stat_text(cond):
    if cond not in an.index: return ""
    r = an.loc[cond]
    p = r["welch_p_holm"]
    ptxt = "p < 0.001" if p < 0.001 else f"p = {p:.3f}"
    return f"Welch F = {r['welch_F']:.1f}, {ptxt}, $\\eta^2$ = {r['eta_squared']:.2f}"

# ---------- Fig 7: box plots of the groups the ANOVA compares ----------
bh, bs = int(hash_raw["size_bytes"].max()), int(sym["size_bytes"].max())
panels = [
    (f"Hashing @ {bh/1e6:g} MB", hash_raw[hash_raw["size_bytes"] == bh], ["md5", "sha256", "sha3_256"],
     ["MD5", "SHA-256", "SHA3-256"], f"hash @ {bh:,} B"),
    (f"Symmetric encrypt @ {bs/1e6:g} MB", sym[(sym["size_bytes"] == bs) & (sym["operation"] == "encrypt")],
     SYM, ["AES-GCM", "ChaCha20", "3DES"], f"symmetric encrypt @ {bs:,} B"),
    ("Asymmetric: sign", asym_raw[asym_raw["operation"] == "sign"], ASYM,
     ["RSA-2048", "ECDSA", "Ed25519"], "asymmetric sign"),
]
fig, axes = plt.subplots(1, 3, figsize=(12, 4.3))
rng = np.random.default_rng(1)
for ax, (title, d, order, labels, cond) in zip(axes, panels):
    data = [d[d["algorithm"] == a]["y"].to_numpy() for a in order]
    ax.boxplot(data, tick_labels=labels, showfliers=False, widths=.5)
    for i, v in enumerate(data, 1):
        ax.scatter(i + rng.uniform(-.12, .12, len(v)), v, s=8, alpha=.5, color="#1f77b4", zorder=3)
    ax.set_title(title, fontsize=10); ax.set_xlabel(stat_text(cond), fontsize=8)
axes[0].set_ylabel("log10( time in seconds )")
fig.suptitle("Groups compared by one-way Welch ANOVA (each dot = one repetition)")
fig.tight_layout(); fig.savefig(F / "fig7_anova_boxplots.png"); plt.close(fig); print("saved fig7")

# ---------- Fig 8: interaction plot (algorithm x input size) ----------
def interaction(ax, df, algos, labels, title):
    for a, lab in zip(algos, labels):
        g = df[df["algorithm"] == a].groupby("size_bytes")["y"]
        m, se = g.mean(), g.sem()
        ax.errorbar(m.index, m.values, yerr=(1.96 * se).values, marker="o", capsize=3, label=lab)
    ax.set_xscale("log"); ax.set_xlabel("Input size (bytes, log scale)"); ax.set_title(title)
fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
interaction(axes[0], hash_raw, ["md5", "sha256", "sha3_256"], ["MD5", "SHA-256", "SHA3-256"], "Hashing")
interaction(axes[1], sym[sym["operation"] == "encrypt"], SYM, ["AES-GCM", "ChaCha20", "3DES"], "Symmetric (encrypt)")
axes[0].set_ylabel("Mean log10(time in seconds) with 95% CI"); axes[0].legend(); axes[1].legend()
fig.suptitle("Interaction plot: non-parallel lines indicate an algorithm x size interaction")
fig.tight_layout(); fig.savefig(F / "fig8_interaction.png"); plt.close(fig); print("saved fig8")

# ---------- Fig 9: Q-Q plots of ANOVA residuals (normality check) ----------
def residuals(df, keys):
    return df["y"] - df.groupby(keys)["y"].transform("mean")
fig, axes = plt.subplots(1, 3, figsize=(11.5, 3.9))
for ax, (title, df, keys) in zip(axes, [
        ("Hashing", hash_raw, ["algorithm", "size_bytes"]),
        ("Symmetric (encrypt)", sym[sym["operation"] == "encrypt"], ["algorithm", "size_bytes"]),
        ("Asymmetric (sign)", asym_raw[asym_raw["operation"] == "sign"], ["algorithm"])]):
    res = residuals(df, keys).to_numpy()
    stats.probplot(res, dist="norm", plot=ax)
    ax.set_title(title, fontsize=10); ax.set_xlabel("Theoretical quantiles"); ax.set_ylabel("Residuals (log10 s)")
fig.suptitle("Normal Q-Q plots of ANOVA residuals (points near the line = approximately normal)")
fig.tight_layout(); fig.savefig(F / "fig9_qq_residuals.png"); plt.close(fig); print("saved fig9")
print("Done. Figures are in:", F.resolve())