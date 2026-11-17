# Comparative Performance and Security Analysis of Cryptographic Algorithms

![Python](https://img.shields.io/badge/Python-3.12.10-blue.svg)
![Course](https://img.shields.io/badge/RMIT-COSC2539%20%7C%20COSC2716-red.svg)
![Statistics](https://img.shields.io/badge/Analysis-Welch's%20ANOVA%20%7C%20Kruskal--Wallis-green.svg)

An empirical Python benchmarking, integrity verification, and statistical analysis suite evaluating **nine cryptographic algorithms** across hashing, symmetric encryption, asymmetric operations, and hybrid encryption pipelines. Developed for the *Analytical Security Report* (COSC2539 / COSC2716 - Security in Computing and Information Technology, RMIT University).

---

## Overview

Selecting cryptographic primitives requires balancing computational throughput, spatial overhead, and security guarantees rather than optimizing for raw speed alone. This repository automates high-resolution timing benchmarks (`time.perf_counter_ns`), ciphertext bit-flip tamper simulations, and parametric/non-parametric statistical hypothesis testing across **3,150 timed executions** to quantify real-world performance and security trade-offs.

### Evaluated Cryptographic Domains

| Domain | Algorithms & Schemes | Input / Operation Scope | Security Services Evaluated |
| :--- | :--- | :--- | :--- |
| **Hashing** | MD5, SHA-256, SHA3-256 | $1\text{ KB}$ to $100\text{ MB}$ payloads ($6$ sizes) | Integrity, Collision Resistance |
| **Symmetric Ciphers** | AES-256-GCM, ChaCha20-Poly1305, ChaCha20 (raw), 3DES-CBC | $1\text{ KB}$ to $100\text{ MB}$ encrypt & decrypt | Confidentiality, AEAD Integrity |
| **Asymmetric Schemes** | RSA-2048 (PSS), ECDSA P-256, Ed25519 | Keygen, Sign ($1\text{ KB}$), Verify ($1\text{ KB}$), DER Key/Sig Sizes | Authentication, Non-Repudiation |
| **Hybrid Pipelines** | `ECDH P-256 + HKDF-SHA256 + AES-256-GCM` vs. `RSA-OAEP + AES-256-GCM` | $1\text{ KB}$, $1\text{ MB}$, and $10\text{ MB}$ end-to-end payloads | Key Establishment, Confidentiality, Integrity |

---

## Repository Structure

```text
.
├── verify_algorithms.py         # Suite of 21 correctness unit tests across all primitives
├── benchmark.py                 # High-resolution timing & tamper test runner (3,150 records)
├── anova_analyze.py             # Statistical pipeline (Levene, Welch's ANOVA, Kruskal-Wallis, Tukey HSD)
├── plot_results.py              # Publication-grade figure generator
├── requirements.txt             # Exact Python package versions for reproducibility
├── results/                     # Raw CSV measurements, statistical summaries, and system info
│   ├── env_info.txt             # Hardware, OS, and Python runtime specifications
│   ├── hash_raw.csv / hash_summary.csv
│   ├── symmetric_raw.csv / symmetric_summary.csv
│   ├── asymmetric_raw.csv / asymmetric_summary.csv / asymmetric_sizes.csv
│   ├── hybrid_raw.csv / hybrid_summary.csv
│   ├── tamper_results.csv       # 100-trial ciphertext bit-flip detection logs
│   └── anova_oneway.csv / anova_twoway.csv / anova_posthoc.csv
└── figures/                     # Generated visual charts and summary tables
    ├── key_results.csv
    ├── captions.txt
    └── fig0_security_services.png ... fig9_qq_residuals.png
```

---

## Key Experimental Findings

### 1. Hashing Throughput ($100\text{ MB}$ Payload)
* **SHA-256** achieved the highest throughput at **$2,492\text{ MB/s}$**, outperforming **SHA3-256** ($764\text{ MB/s}$) by over $3\times$.
* **MD5** reached $1,090\text{ MB/s}$ but remains cryptographically broken due to practical collision vulnerabilities.
* Two-way ANOVA confirmed a significant algorithm-by-size interaction ($F(10) = 95.65, p < .001, \text{partial } \eta^2 = 0.647$).

### 2. Symmetric Encryption & Tamper Resistance ($100\text{ MB}$ Payload)
* **AES-256-GCM** led all ciphers at **$2,907\text{ MB/s}$** (encryption) and **$3,066\text{ MB/s}$** (decryption), followed by **ChaCha20-Poly1305** at **$1,701\text{ MB/s}$**.
* **Tamper Detection ($100$ Bit-Flip Trials):** Authenticated modes (**AES-256-GCM** and **ChaCha20-Poly1305**) rejected **$100/100$** corrupted ciphertexts via tag validation failures. Unauthenticated **ChaCha20 (raw)** ($2,333\text{ MB/s}$) and deprecated **3DES-CBC** ($14.4\text{ MB/s}$) silently accepted **$100/100$** corrupted plaintexts without raising errors.

### 3. Asymmetric Operations & Footprint
| Algorithm | Median Keygen | Median Sign ($1\text{ KB}$) | Median Verify ($1\text{ KB}$) | Private Key (DER) | Public Key (DER) | Signature |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **RSA-2048 (PSS)** | $22.70\text{ ms}$ | $371.6\ \mu\text{s}$ | **$23.8\ \mu\text{s}$** | $1,216\text{ B}$ | $294\text{ B}$ | $256\text{ B}$ |
| **ECDSA P-256** | **$9.8\ \mu\text{s}$** | **$17.0\ \mu\text{s}$** | $51.8\ \mu\text{s}$ | $138\text{ B}$ | $91\text{ B}$ | $71\text{ B}$ |
| **Ed25519** | $20.8\ \mu\text{s}$ | $23.0\ \mu\text{s}$ | $62.6\ \mu\text{s}$ | **$48\text{ B}$** | **$44\text{ B}$** | **$64\text{ B}$** |

### 4. Hybrid Encryption Pipelines
* **Small Payloads ($1\text{ KB}$):** `ECDH P-256 + HKDF + AES-GCM` completed in **$101.7\ \mu\text{s}$**, nearly $4\times$ faster than `RSA-OAEP + AES-GCM` ($398.7\ \mu\text{s}$).
* **Large Payloads ($10\text{ MB}$):** Symmetric bulk encryption dominated total execution time, narrowing the gap ($8.40\text{ ms}$ for ECDH vs. $8.81\text{ ms}$ for RSA-OAEP; $\eta^2 = 0.125$).
* **Ciphertext Overhead:** ECDH added **$93\text{ bytes}$** per message compared to **$284\text{ bytes}$** for RSA-OAEP.

---

## Experimental Methodology & Environment

* **Hardware & OS:** Intel Core i5-14600KF ($14$ cores, $20$ threads), $31.8\text{ GB}$ RAM, Windows 10 (Build 19045), Python `3.12.10` (64-bit).
* **Cryptographic Libraries:** Python standard library `hashlib`, `cryptography==50.0.2`, and `pycryptodome==4.3.0`.
* **Measurement Protocol:** $3$ warm-up runs followed by $30$ timed repetitions ($100$ repetitions for microsecond-scale asymmetric operations) using unseeded `os.urandom` payloads and fresh nonces/IVs per run.
* **Statistical Validation:** Because timing distributions were right-skewed and Levene's test rejected homoscedasticity in $13/24$ conditions, inference was performed on $\log_{10}$-transformed execution times using **Welch's one-way ANOVA**, **Kruskal-Wallis** non-parametric checks, and **Holm-corrected Tukey's HSD** post-hoc tests.

---

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Correctness Verification
Validate all cryptographic primitives and round-trip assertions ($21$ automated tests):
```bash
python verify_algorithms.py
```

### 3. Run Benchmarks, Statistical Analysis, and Plots
```bash
python benchmark.py
python anova_analyze.py
python plot_results.py
```

---

## Author & Acknowledgements

* **Author:** Phan Phuc Chanh (`s4134508`) — RMIT University
* **Academic Integrity Note:** Generative AI tools (Anthropic Claude and Google Gemini) were used to assist with structuring benchmark scripts, checking consistency between figures and report text, and refining documentation formatting, with all code execution, datasets, and statistical outputs independently verified by the author.
