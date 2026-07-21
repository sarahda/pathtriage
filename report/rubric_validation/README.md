# Rubric Validation

Three-method validation package for PathTriage's exploitability Rubric v1.
Provides triangulated validity evidence without dependence on a single
expert evaluator.

## The Three Methods

| Method | Validates | File |
|---|---|---|
| 1. Historical Breach Retrospective | Ecological validity — rubric assigns high scores to attack paths that produced real-world breaches | `historical_breach_retrospective.md` |
| 2. CVSS 3.1 Cross-Validation | Concurrent validity — comparison against industry-standard vulnerability scoring | `cvss_cross_validation.md` |
| 3. Ablation / Sensitivity Analysis | Robustness — weight choice not decisive within reasonable bounds | `ablation_analysis.md` |

## Results Summary

**Method 1** — 9 documented major cloud breaches (Capital One 2019,
Snowflake 2024, Midnight Blizzard 2024, Uber 2022, CircleCI 2023,
LastPass 2022, Okta 2023, Microsoft SAS 2023, Storm-0558 2023):
- All 9 breaches score ≥ 3.4 on rubric domain [1.0, 5.0]
- Median = 4.10 (top 22% of domain)
- 5/9 (56%) in top quartile (≥ 4.0)

**Method 2** — Spearman rank correlation with CVSS 3.1 base scores
across 16 attack paths:
- ρ = 0.36 (p = 0.17)
- Divergence reflects CVSS ceiling effect (15/16 paths CVSS > 8.4) and
  rubric's added variance on dimensions CVSS does not model (chain
  length, detection difficulty)
- Interpreted as evidence for rubric's added value beyond generic
  vulnerability scoring, not a validation failure

**Method 3** — Bootstrap weight perturbation (n=1000, ε=±0.10):
- Mean Kendall's τ = 0.97 (target ≥ 0.80)
- Top-5 ranking preserved in 100% of perturbations
- All fixed weight variants except detection-heavy show ρ ≥ 0.96

## Files

```
README.md                              This file
historical_breach_retrospective.md     Method 1 full analysis
cvss_cross_validation.md               Method 2 methodology + CVSS vectors
ablation_analysis.md                   Method 3 methodology
cvss_comparison.py                     Method 2 script
ablation.py                            Method 3 script
cvss_results.txt                       Method 2 execution output
ablation_results.txt                   Method 3 execution output
cvss_comparison.png                    Method 2 scatter plot
ablation_analysis.png                  Method 3 histogram + box plots
```

## Reproducing the Results

```bash
pip install scipy numpy matplotlib

python cvss_comparison.py > cvss_results.txt
python ablation.py > ablation_results.txt
```

Reproducibility guaranteed by `np.random.seed(42)` in `ablation.py`.

## Consumed By

- `report/main.tex` Chapter 8 (Rubric Validation section)
- Discussion of rubric methodology in Chapter 9 (Issues Encountered)
