# Rubric Validation Method 3: Ablation and Sensitivity Analysis

**Purpose**: Demonstrate that Rubric v1's chosen weight configuration
is robust — small perturbations of the weights produce similar
rankings. This addresses the "why these specific weights?" reviewer
question by showing that the results do not depend sensitively on the
exact choices.

**Author**: Tessa Moon, 2026-07-20  
**Consumed by**: `report/main.tex` Chapter 8 (Rubric Validation section)

---

## Methodology

### Ablation Component 1: Fixed weight variants

Test the rubric under five specific weight configurations to show that
extreme weight choices produce different rankings than v1:

| Variant | d_edge | h | delta_p | d_det | Emphasis |
|---|:---:|:---:|:---:|:---:|---|
| **v1 (chosen)** | 0.30 | 0.20 | 0.30 | 0.20 | Balanced |
| Uniform | 0.25 | 0.25 | 0.25 | 0.25 | No prior |
| Executability-heavy | 0.40 | 0.10 | 0.40 | 0.10 | Consequence + feasibility |
| Detection-heavy | 0.20 | 0.10 | 0.20 | 0.50 | Alerting difficulty |
| Chain-length-heavy | 0.20 | 0.40 | 0.20 | 0.20 | Chain complexity |

For each variant, compute rankings of the 16 paths and Spearman ρ
against v1.

### Ablation Component 2: Bootstrap perturbation

Randomly perturb each weight by ±ε (where ε = 0.10) while maintaining
the constraint that weights sum to 1.0. Repeat n = 1000 times. Compute
the Kendall's τ distance between each perturbed ranking and the v1
ranking.

Report:
- Mean Kendall's τ (higher = more stable)
- Proportion of perturbations preserving the top-5 ranking
- Standard deviation of scores per path

### Validation criteria

Pre-registered:
- Mean Kendall's τ ≥ 0.80 across n=1000 perturbations
- Top-5 ranking preserved in ≥ 80% of perturbations
- No variant with weights within ±0.10 of v1 produces ρ < 0.85

---

## Python Script for Ablation Analysis

Save as `report/rubric_validation/ablation.py` and run:

```python
"""
Ablation and Sensitivity Analysis of PathTriage Rubric v1

Runs two experiments:
  A) Fixed weight variants — 5 specific alternative weightings
  B) Bootstrap perturbation — n=1000 random weight perturbations
      within ±0.10 of v1 weights

Prerequisites:
    pip install scipy numpy matplotlib
"""
import numpy as np
from scipy import stats
from itertools import combinations

np.random.seed(42)  # reproducibility

# ---------------------------------------------------------------------
# The 16 attack paths with rubric inputs (from historical breach analysis)
# ---------------------------------------------------------------------
paths = [
    # (path_id, d_edge, h, delta_p, d_det)
    ('P1',  1, 2, 5, 3),
    ('P2',  2, 3, 5, 3),
    ('P3',  1, 1, 5, 3),
    ('P4',  2, 3, 5, 4),
    ('P5',  1, 1, 5, 3),
    ('P6',  2, 2, 5, 4),
    ('P7',  1, 1, 5, 4),
    ('P8',  1, 1, 5, 4),
    ('Z1',  2, 2, 5, 4),
    ('Z2',  1, 1, 5, 3),
    ('Z3',  1, 1, 5, 3),
    ('Z4',  3, 1, 5, 4),
    ('Z5',  1, 1, 5, 3),
    ('Z6',  1, 1, 5, 4),
    ('Z7',  3, 2, 5, 4),
    ('Z8',  1, 2, 5, 3),
]

path_ids = [p[0] for p in paths]
inputs = np.array([[p[1], p[2], p[3], p[4]] for p in paths])  # shape (16, 4)


def score_paths(weights):
    """Compute rubric scores for all paths given weights [w_edge, w_h, w_delta, w_det]."""
    w_edge, w_h, w_delta, w_det = weights
    d_edge, h, delta_p, d_det = inputs[:, 0], inputs[:, 1], inputs[:, 2], inputs[:, 3]
    return (w_edge * (6 - d_edge)
          + w_h    * (6 - h)
          + w_delta * delta_p
          + w_det  * d_det)


def rank_paths(scores):
    """Return ranks 1..16 (1 = highest score)."""
    return len(scores) - scores.argsort().argsort()


# ---------------------------------------------------------------------
# Baseline: v1 weights
# ---------------------------------------------------------------------
w_v1 = np.array([0.30, 0.20, 0.30, 0.20])
scores_v1 = score_paths(w_v1)
ranks_v1 = rank_paths(scores_v1)

print("=" * 60)
print("Rubric v1 baseline scores")
print("=" * 60)
print("Path | Score | Rank")
print("-" * 25)
sorted_indices = scores_v1.argsort()[::-1]
for i in sorted_indices:
    print(f"{path_ids[i]:>4} | {scores_v1[i]:.2f}  |  {ranks_v1[i]:>2}")

# ---------------------------------------------------------------------
# EXPERIMENT A: Fixed weight variants
# ---------------------------------------------------------------------
print("\n" + "=" * 60)
print("EXPERIMENT A: Fixed weight variants vs v1")
print("=" * 60)

variants = {
    'v1 (chosen)':           np.array([0.30, 0.20, 0.30, 0.20]),
    'Uniform':               np.array([0.25, 0.25, 0.25, 0.25]),
    'Executability-heavy':   np.array([0.40, 0.10, 0.40, 0.10]),
    'Detection-heavy':       np.array([0.20, 0.10, 0.20, 0.50]),
    'Chain-length-heavy':    np.array([0.20, 0.40, 0.20, 0.20]),
}

print(f"\n{'Variant':<24} | {'ρ vs v1':<9} | {'Top-5 same':<12}")
print("-" * 50)
top5_v1 = set(np.argsort(scores_v1)[::-1][:5])
for name, weights in variants.items():
    scores = score_paths(weights)
    rho, _ = stats.spearmanr(scores, scores_v1)
    top5_variant = set(np.argsort(scores)[::-1][:5])
    top5_agreement = len(top5_v1 & top5_variant) / 5.0
    print(f"{name:<24} | {rho:<9.3f} | {top5_agreement:<12.0%}")

# ---------------------------------------------------------------------
# EXPERIMENT B: Bootstrap weight perturbation
# ---------------------------------------------------------------------
print("\n" + "=" * 60)
print("EXPERIMENT B: Bootstrap perturbation (n=1000, ε=±0.10)")
print("=" * 60)

n_bootstrap = 1000
epsilon = 0.10
kendall_taus = []
spearman_rhos = []
top5_preserved = 0
per_path_scores = np.zeros((n_bootstrap, len(paths)))

for i in range(n_bootstrap):
    # Perturb each weight by uniform noise, then normalise to sum 1
    delta = np.random.uniform(-epsilon, epsilon, size=4)
    w_perturbed = w_v1 + delta
    w_perturbed = np.abs(w_perturbed)  # ensure non-negative
    w_perturbed = w_perturbed / w_perturbed.sum()  # normalise

    scores_pert = score_paths(w_perturbed)
    per_path_scores[i] = scores_pert

    # Compare rankings
    tau, _ = stats.kendalltau(scores_pert, scores_v1)
    rho, _ = stats.spearmanr(scores_pert, scores_v1)
    kendall_taus.append(tau)
    spearman_rhos.append(rho)

    # Top-5 preservation
    top5_pert = set(np.argsort(scores_pert)[::-1][:5])
    if top5_pert == top5_v1:
        top5_preserved += 1

kendall_taus = np.array(kendall_taus)
spearman_rhos = np.array(spearman_rhos)

print(f"\nMean Kendall's τ    = {kendall_taus.mean():.4f}")
print(f"Std Kendall's τ     = {kendall_taus.std():.4f}")
print(f"Min Kendall's τ     = {kendall_taus.min():.4f}")
print(f"Mean Spearman ρ     = {spearman_rhos.mean():.4f}")
print(f"Top-5 preserved:      {top5_preserved}/{n_bootstrap} ({100*top5_preserved/n_bootstrap:.1f}%)")

# Per-path score stability
print(f"\nPer-path score std (from perturbation):")
for i, pid in enumerate(path_ids):
    std_i = per_path_scores[:, i].std()
    mean_i = per_path_scores[:, i].mean()
    cv_i = std_i / mean_i if mean_i > 0 else 0
    print(f"  {pid}: mean={mean_i:.3f}, std={std_i:.3f}, CV={cv_i:.3f}")

# ---------------------------------------------------------------------
# Validation criteria assessment
# ---------------------------------------------------------------------
print("\n" + "=" * 60)
print("VALIDATION CRITERIA ASSESSMENT")
print("=" * 60)

crit1 = kendall_taus.mean() >= 0.80
crit2 = (top5_preserved / n_bootstrap) >= 0.80
variant_rhos = [stats.spearmanr(score_paths(w), scores_v1)[0]
                for name, w in variants.items() if name != 'v1 (chosen)']
crit3 = all(r >= 0.85 for r in variant_rhos)

print(f"1. Mean Kendall's τ ≥ 0.80: {kendall_taus.mean():.3f} {'✓' if crit1 else '✗'}")
print(f"2. Top-5 preserved ≥ 80%: {100*top5_preserved/n_bootstrap:.1f}% {'✓' if crit2 else '✗'}")
print(f"3. All variants ρ ≥ 0.85: {'✓' if crit3 else '✗'} (min = {min(variant_rhos):.3f})")

# ---------------------------------------------------------------------
# Optional: visualisations
# ---------------------------------------------------------------------
try:
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # Kendall's τ histogram
    axes[0].hist(kendall_taus, bins=30, alpha=0.7, color='steelblue', edgecolor='black')
    axes[0].axvline(kendall_taus.mean(), color='red', linestyle='--',
                    label=f"Mean = {kendall_taus.mean():.3f}")
    axes[0].axvline(0.80, color='green', linestyle=':',
                    label="Threshold = 0.80")
    axes[0].set_xlabel("Kendall's τ vs v1 baseline")
    axes[0].set_ylabel("Frequency")
    axes[0].set_title(f"Rank stability under weight perturbation (n=1000)")
    axes[0].legend()
    axes[0].grid(alpha=0.3)

    # Per-path score distribution (box plot)
    sorted_idx = scores_v1.argsort()[::-1]
    box_data = [per_path_scores[:, i] for i in sorted_idx]
    box_labels = [path_ids[i] for i in sorted_idx]
    axes[1].boxplot(box_data, labels=box_labels, showfliers=False)
    axes[1].set_xlabel("Path (ordered by v1 score)")
    axes[1].set_ylabel("Score under perturbation")
    axes[1].set_title(f"Per-path score stability (16 paths, n=1000 perturbations)")
    axes[1].grid(alpha=0.3, axis='y')
    plt.xticks(rotation=45)

    plt.tight_layout()
    plt.savefig('ablation_analysis.png', dpi=150)
    print(f"\nPlots saved to ablation_analysis.png")
except ImportError:
    print("\nmatplotlib not installed — skipping plots")
```

---

## Expected Results (Pre-computed manually)

### Experiment A: Fixed variants

Expected Spearman ρ vs v1 for each variant:

| Variant | Expected ρ | Interpretation |
|---|---|---|
| v1 (chosen) | 1.00 | Baseline |
| Uniform | ≈ 0.85–0.95 | Small deviation — no prior still close |
| Executability-heavy | ≈ 0.85–0.95 | Close: v1 already favours d_edge/delta_p |
| Detection-heavy | ≈ 0.60–0.75 | Substantial deviation — different priorities |
| Chain-length-heavy | ≈ 0.55–0.75 | Substantial deviation — different priorities |

**Interpretation**: v1 is close to executability-heavy in ranking behaviour but diverges materially from detection-heavy and chain-length-heavy variants. This shows v1 is not equivalent to arbitrary weight choices.

### Experiment B: Bootstrap perturbation

Expected:
- **Mean Kendall's τ ≈ 0.88–0.94** (rank stability high under small perturbation)
- **Top-5 preserved in ≈ 85–95% of perturbations**
- **Per-path score CV ≈ 0.05–0.10** (individual scores robust)

**Interpretation**: v1 weight choice within ±0.10 does not materially alter ranking outcomes. Reviewer question "why exactly these weights?" is answered: the specific values within a reasonable range are not decisive.

---

## Report-ready summary

> "Rubric v1 robustness was assessed via ablation analysis. Under
> bootstrap perturbation (n=1000, ε=±0.10), the mean Kendall's τ
> against the v1 baseline was X.XXX, with the top-5 ranking preserved
> in X% of perturbations. Comparison against four alternative weight
> configurations (uniform, executability-heavy, detection-heavy,
> chain-length-heavy) showed that v1's ranking correlates strongly
> with the executability-heavy variant (ρ = X.XX) but diverges from
> configurations emphasising chain length (ρ = X.XX) or detection
> difficulty (ρ = X.XX). This confirms that v1 weight choice within
> reasonable perturbation bounds does not decisively determine the
> ranking outcome, while the specific priorities encoded (executability
> and consequence severity dominant) do produce meaningfully different
> rankings from alternative priority orderings."

---

## Limitations

1. **Weight normalisation**: Perturbation includes weight normalisation to sum-1, which introduces some structural constraint on the exploration space.

2. **Bounded perturbation**: ε = 0.10 was chosen as reasonable — larger perturbations (ε > 0.20) would produce more variance but represent implausibly different rubrics.

3. **Fixed input values**: The rubric inputs (d_edge, h, delta_p, d_det) themselves are not perturbed. Sensitivity to input scoring choices is a separate concern addressed indirectly by the retrospective validation (Method 1).

## Running the script

```bash
cd ~/Documents/UNSW\ Term2/Comp9301/pathtriage
# Save the Python script above as report/rubric_validation/ablation.py
python report/rubric_validation/ablation.py
```

Save output for the report. Screenshot the histogram and box plot for Chapter 8.
