"""
anova_analysis.py - inferential statistics for the benchmark data.
Run: python anova_analysis.py        (after benchmark.py)
Outputs (in ./results):
  anova_oneway.csv   one-way Welch ANOVA + Kruskal-Wallis per condition
  anova_posthoc.csv  Tukey HSD pairwise comparisons
  anova_twoway.csv   two-way ANOVA (algorithm x input size) per family
"""
from pathlib import Path
import numpy as np
import pandas as pd
from scipy import stats
import statsmodels.api as sm
import statsmodels.formula.api as smf
from statsmodels.stats.multicomp import pairwise_tukeyhsd
from statsmodels.stats.multitest import multipletests
from statsmodels.stats.oneway import anova_oneway

R = Path("results")
hash_raw = pd.read_csv(R / "hash_raw.csv")
sym_raw = pd.read_csv(R / "symmetric_raw.csv")
asym_raw = pd.read_csv(R / "asymmetric_raw.csv")
hyb_raw = pd.read_csv(R / "hybrid_raw.csv")

# The three assigned symmetric algorithms. Add "ChaCha20-Poly1305" to compare it too.
SYM_ALGOS = ["AES-256-GCM", "ChaCha20 (raw)", "3DES-CBC"]
ASYM_ALGOS = ["RSA-2048 (PSS)", "ECDSA P-256", "Ed25519"]

def one_way(df, group_col, label):
    """Run the tests for one condition. Returns (result dict, posthoc rows)."""
    d = df.copy()
    d["y"] = np.log10(d["time_s"])
    groups = {k: g["y"].to_numpy() for k, g in d.groupby(group_col)}
    arrays = list(groups.values())
    res = {"condition": label, "groups": " | ".join(groups), "n_per_group": len(arrays[0])}
    try:
        w = anova_oneway(arrays, use_var="unequal", welch_correction=True)
        res.update(welch_F=w.statistic, welch_df1=w.df_num, welch_df2=w.df_denom, welch_p=w.pvalue)
    except Exception:
        res.update(welch_F=np.nan, welch_df1=np.nan, welch_df2=np.nan, welch_p=np.nan)
    try:
        res["levene_p"] = stats.levene(*arrays).pvalue
        res["kruskal_H"], res["kruskal_p"] = stats.kruskal(*arrays)
    except Exception:
        res.update(levene_p=np.nan, kruskal_H=np.nan, kruskal_p=np.nan)
    allv = np.concatenate(arrays); grand = allv.mean()
    ssb = sum(len(a) * (a.mean() - grand) ** 2 for a in arrays)
    sst = ((allv - grand) ** 2).sum()
    res["eta_squared"] = ssb / sst if sst > 0 else np.nan
    post = []
    if len(arrays) > 2:
        try:
            tk = pairwise_tukeyhsd(d["y"], d[group_col])
            for row in tk.summary().data[1:]:
                post.append({"condition": label, "group1": row[0], "group2": row[1],
                             "mean_diff_log10": row[2], "p_adj": row[3], "reject_H0": row[6],
                             "ratio_g2_over_g1": 10 ** row[2]})
        except Exception:
            pass
    return res, post

def run_family(name, frames):
    """frames: list of (label, DataFrame, group_col)."""
    results, posts = [], []
    for label, df, col in frames:
        r, p = one_way(df, col, label); r["family"] = name
        results.append(r); posts += [dict(family=name, **x) for x in p]
    out = pd.DataFrame(results)
    ok = out["welch_p"].notna()
    out["welch_p_holm"] = np.nan
    if ok.any():
        out.loc[ok, "welch_p_holm"] = multipletests(out.loc[ok, "welch_p"], method="holm")[1]
    return out, posts

all_res, all_post = [], []

# ---- Hashing: one-way ANOVA across algorithms at each input size ----
frames = [(f"hash @ {int(s):,} B", g, "algorithm") for s, g in hash_raw.groupby("size_bytes")]
r, p = run_family("hash", frames); all_res.append(r); all_post += p

# ---- Symmetric: per input size and operation (encrypt / decrypt) ----
sym = sym_raw[sym_raw["algorithm"].isin(SYM_ALGOS)]
frames = [(f"symmetric {op} @ {int(s):,} B", g, "algorithm")
          for (op, s), g in sym.groupby(["operation", "size_bytes"])]
r, p = run_family("symmetric", frames); all_res.append(r); all_post += p

# ---- Asymmetric: per operation across the three signature schemes ----
asym = asym_raw[asym_raw["algorithm"].isin(ASYM_ALGOS)]
frames = [(f"asymmetric {op}", g, "algorithm") for op, g in asym.groupby("operation")]
r, p = run_family("asymmetric", frames); all_res.append(r); all_post += p

# ---- Hybrid: two pipelines at each size (Welch ANOVA = Welch t-test) ----
frames = [(f"hybrid @ {int(s):,} B", g, "pipeline") for s, g in hyb_raw.groupby("size_bytes")]
r, p = run_family("hybrid", frames); all_res.append(r)

res = pd.concat(all_res, ignore_index=True)
cols = ["family", "condition", "groups", "n_per_group", "welch_F", "welch_df1", "welch_df2",
        "welch_p", "welch_p_holm", "eta_squared", "levene_p", "kruskal_H", "kruskal_p"]
res[cols].to_csv(R / "anova_oneway.csv", index=False)
pd.DataFrame(all_post).to_csv(R / "anova_posthoc.csv", index=False)

# ---- Two-way ANOVA: algorithm x input size (log10 time) per family ----
tw = []
for fam, df in (("hash", hash_raw), ("symmetric", sym)):
    d = df.copy(); d["y"] = np.log10(d["time_s"])
    if fam == "symmetric":
        d = d[d["operation"] == "encrypt"]
    model = smf.ols("y ~ C(algorithm) * C(size_bytes)", data=d).fit()
    table = sm.stats.anova_lm(model, typ=2)
    ss_res = table.loc["Residual", "sum_sq"]
    for term, row in table.iterrows():
        if term == "Residual": continue
        tw.append({"family": fam + (" (encrypt)" if fam == "symmetric" else ""), "term": term,
                   "df": row["df"], "F": row["F"], "p": row["PR(>F)"],
                   "partial_eta_sq": row["sum_sq"] / (row["sum_sq"] + ss_res)})
pd.DataFrame(tw).to_csv(R / "anova_twoway.csv", index=False)

# ---- Console summary ----
pd.set_option("display.width", 200, "display.max_columns", 20)
print(res[["condition", "welch_F", "welch_p_holm", "eta_squared", "levene_p"]].round(4).to_string(index=False))
print("\nTwo-way ANOVA (algorithm x size):")
print(pd.DataFrame(tw).round(4).to_string(index=False))
print("\nSaved anova_oneway.csv, anova_posthoc.csv, anova_twoway.csv in", R.resolve())