"""
CVSS 3.1 Cross-Validation of PathTriage Rubric v1

Computes Spearman rank correlation between rubric scores and CVSS 3.1
base scores for the 16 attack paths in the catalogue.

Improved scatter plot: groups paths that share the same (CVSS, Rubric)
coordinates into a single labelled marker, with marker size proportional
to group size. Eliminates label overlap.

Prerequisites:
    pip install scipy numpy matplotlib
"""
import numpy as np
from scipy import stats
from collections import defaultdict

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

r, r_p = stats.pearsonr(rubric_scores, cvss_scores)
print(f"\nPearson r    = {r:.4f}")
print(f"p-value      = {r_p:.4f}")

# ---------------------------------------------------------------------
# Group paths at identical coordinates (this is the ceiling effect)
# ---------------------------------------------------------------------
coord_groups = defaultdict(list)
for pid, cs, rs in zip(path_ids, cvss_scores, rubric_scores):
    coord_groups[(round(cs, 2), round(rs, 2))].append(pid)

print(f"\n--- Coordinate groups (visualising CVSS ceiling effect) ---")
for (cs, rs), pids in sorted(coord_groups.items()):
    print(f"  CVSS={cs}, Rubric={rs}: {', '.join(sorted(pids))} ({len(pids)} path{'s' if len(pids)>1 else ''})")

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
    print(f"\n[X] rho = {rho:.3f}. Weak correlation with CVSS -- driven by ceiling effect (see coordinate groups above)")

# ---------------------------------------------------------------------
# Improved scatter plot with grouped labels
# ---------------------------------------------------------------------
try:
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(11, 7.5))

    # Plot markers: size proportional to number of paths at coordinate
    for (cs, rs), pids in coord_groups.items():
        n = len(pids)
        # Base size 120, +80 per additional path at same coordinate
        size = 120 + 80 * (n - 1)
        ax.scatter(cs, rs, s=size, alpha=0.65, color='steelblue',
                   edgecolor='navy', linewidth=1.5, zorder=3)

    # Regression line
    z = np.polyfit(cvss_scores, rubric_scores, 1)
    p = np.poly1d(z)
    x_line = np.linspace(cvss_scores.min() - 0.1, cvss_scores.max() + 0.1, 100)
    ax.plot(x_line, p(x_line), 'r--', alpha=0.5, linewidth=1.5,
            label=f'Linear fit: y = {z[0]:.3f}x + {z[1]:.3f}', zorder=2)

    # Smart label placement: offset by position on plot
    # Right side of plot (CVSS ~9.9) -> labels to the left
    # Left side of plot (CVSS ~8.4) -> labels to the right
    for (cs, rs), pids in coord_groups.items():
        label = ", ".join(sorted(pids))

        # Choose label offset based on coordinate position
        if cs >= 9.5:
            xytext_offset = (-15, 0)
            ha = 'right'
        elif cs <= 8.6:
            xytext_offset = (15, 0)
            ha = 'left'
        else:  # middle
            xytext_offset = (0, 15)
            ha = 'center'

        ax.annotate(label, (cs, rs),
                    xytext=xytext_offset, textcoords='offset points',
                    fontsize=10, ha=ha, va='center',
                    bbox=dict(boxstyle='round,pad=0.35',
                              facecolor='white',
                              edgecolor='steelblue', alpha=0.9, linewidth=0.8),
                    zorder=4)

    ax.set_xlabel('CVSS 3.1 Base Score', fontsize=12)
    ax.set_ylabel('Rubric v1 Score', fontsize=12)
    ax.set_title(f'PathTriage Rubric v1 vs CVSS 3.1\n'
                 f'Spearman rho = {rho:.3f} (p = {p_value:.4f})    '
                 f'| n = {len(paths)} paths, {len(coord_groups)} unique coordinates',
                 fontsize=13)
    ax.grid(True, alpha=0.3, zorder=1)
    ax.legend(loc='lower right', fontsize=10)

    # Set axis limits with padding
    ax.set_xlim(cvss_scores.min() - 0.3, cvss_scores.max() + 0.3)
    ax.set_ylim(rubric_scores.min() - 0.15, rubric_scores.max() + 0.15)

    plt.tight_layout()
    plt.savefig('cvss_comparison.png', dpi=150, bbox_inches='tight')
    print(f"\nScatter plot saved to cvss_comparison.png")
    print(f"  Marker sizes reflect number of paths at each coordinate")
    print(f"  16 paths compressed to {len(coord_groups)} unique CVSS-Rubric coordinates")
    print(f"  -- this is a visual demonstration of the CVSS ceiling effect")
except ImportError:
    print("\nmatplotlib not installed - skipping plot")
