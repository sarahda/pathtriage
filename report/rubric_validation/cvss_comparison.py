"""
CVSS 3.1 Cross-Validation of PathTriage Rubric v1

Computes Spearman rank correlation between rubric scores and CVSS 3.1
base scores for the 16 attack paths in the catalogue.

Prerequisites:
    pip install scipy numpy matplotlib
"""
import numpy as np
from scipy import stats

# ---------------------------------------------------------------------
# Data: 16 attack paths with rubric and CVSS scores
# ---------------------------------------------------------------------

paths = [
    # (path_id, rubric_d_edge, rubric_h, rubric_delta_p, rubric_d_det, cvss_base)
    ('P1',  1, 2, 5, 3,  9.9),
    ('P2',  2, 3, 5, 3,  9.0),
    ('P3',  1, 1, 5, 3,  9.9),
    ('P4',  2, 3, 5, 4,  9.9),
    ('P5',  1, 1, 5, 3,  9.9),
    ('P6',  2, 2, 5, 4,  8.4),
    ('P7',  1, 1, 5, 4,  8.8),
    ('P8',  1, 1, 5, 4,  8.8),
    ('Z1',  2, 2, 5, 4,  8.4),
    ('Z2',  1, 1, 5, 3,  9.9),
    ('Z3',  1, 1, 5, 3,  9.9),
    ('Z4',  3, 1, 5, 4,  8.5),
    ('Z5',  1, 1, 5, 3,  9.9),
    ('Z6',  1, 1, 5, 4,  9.9),
    ('Z7',  3, 2, 5, 4,  8.5),
    ('Z8',  1, 2, 5, 3,  9.9),
]

# ---------------------------------------------------------------------
# Compute rubric score from inputs (v1 weights: 0.30/0.20/0.30/0.20)
# ---------------------------------------------------------------------
def rubric_score(d_edge, h, delta_p, d_det):
    return (0.30 * (6 - d_edge)
          + 0.20 * (6 - h)
          + 0.30 * delta_p
          + 0.20 * d_det)

# ---------------------------------------------------------------------
# Compute for all paths
# ---------------------------------------------------------------------
path_ids = [p[0] for p in paths]
rubric_scores = np.array([rubric_score(p[1], p[2], p[3], p[4]) for p in paths])
cvss_scores = np.array([p[5] for p in paths])

print("Path | Rubric v1 | CVSS 3.1")
print("-" * 32)
for pid, rs, cs in zip(path_ids, rubric_scores, cvss_scores):
    print(f"{pid:>4} |   {rs:>5.2f}   |  {cs:>5.2f}")

# ---------------------------------------------------------------------
# Spearman rank correlation
# ---------------------------------------------------------------------
rho, p_value = stats.spearmanr(rubric_scores, cvss_scores)
print(f"\nSpearman rho = {rho:.4f}")
print(f"p-value      = {p_value:.4f}")

# Also compute Pearson for comparison
r, r_p = stats.pearsonr(rubric_scores, cvss_scores)
print(f"\nPearson r    = {r:.4f}")
print(f"p-value      = {r_p:.4f}")

# ---------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------
if rho >= 0.70 and p_value < 0.01:
    print(f"\n[OK] VALIDATED: Spearman rho = {rho:.3f} exceeds pre-registered threshold (0.70) with p < 0.01")
elif rho >= 0.70:
    print(f"\n[!] rho >= 0.70 but p-value = {p_value:.4f}. Statistical significance marginal.")
elif rho >= 0.50:
    print(f"\n[!] rho = {rho:.3f}. Moderate correlation, below pre-registered threshold.")
else:
    print(f"\n[X] rho = {rho:.3f}. Weak correlation with CVSS.")

# ---------------------------------------------------------------------
# Optional: scatter plot
# ---------------------------------------------------------------------
try:
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.scatter(cvss_scores, rubric_scores, alpha=0.6, s=80)
    for pid, cs, rs in zip(path_ids, cvss_scores, rubric_scores):
        ax.annotate(pid, (cs, rs), xytext=(5, 5), textcoords='offset points', fontsize=9)

    # Regression line
    z = np.polyfit(cvss_scores, rubric_scores, 1)
    p = np.poly1d(z)
    x_line = np.linspace(cvss_scores.min(), cvss_scores.max(), 100)
    ax.plot(x_line, p(x_line), 'r--', alpha=0.5, label=f'Linear fit: y = {z[0]:.3f}x + {z[1]:.3f}')

    ax.set_xlabel('CVSS 3.1 Base Score', fontsize=11)
    ax.set_ylabel('Rubric v1 Score', fontsize=11)
    ax.set_title(f'PathTriage Rubric v1 vs CVSS 3.1\nSpearman rho = {rho:.3f} (p = {p_value:.4f})', fontsize=12)
    ax.grid(True, alpha=0.3)
    ax.legend()
    plt.tight_layout()
    plt.savefig('cvss_comparison.png', dpi=150)
    print(f"\nScatter plot saved to cvss_comparison.png")
except ImportError:
    print("\nmatplotlib not installed - skipping plot")
