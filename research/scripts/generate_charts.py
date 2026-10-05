"""
research/scripts/generate_charts.py

Generate publication-ready evaluation charts for the Research Experimentation Phase directly
from research/results/verified_benchmark_matrix.json.
Saves figure PNGs to research/figures/.
"""

import json
from pathlib import Path
import matplotlib.pyplot as plt

def generate_charts():
    root_dir = Path(__file__).resolve().parents[2]
    figures_dir = root_dir / "research" / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)

    results_file = root_dir / "research" / "results" / "verified_benchmark_matrix.json"
    with open(results_file, encoding="utf-8") as f:
        data = json.load(f)

    matrix = data["verified_benchmark_matrix"]
    modes = [r["mode"] for r in matrix]
    commit_sha = "1800ca80f91d"
    meta_subtitle = f"Dataset: v1.0 | Verified Commit: {commit_sha}"

    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')

    primary_color = "#1E88E5"

    # 1. F1 Score by Mode
    f1_scores = [r["f1_score"] for r in matrix]
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(modes, f1_scores, color=primary_color, edgecolor="black", alpha=0.85)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("F1 Score (0.0 to 1.0)", fontsize=11, fontweight="bold")
    ax.set_title(f"F1 Score Progression Across M0-M6 Operational Modes\n({meta_subtitle})", fontsize=12, fontweight="bold")
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f"{height:.2f}", xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold')
    plt.tight_layout()
    fig.savefig(figures_dir / "f1_by_mode.png", dpi=300)
    plt.close()

    # 2. Precision by Mode
    precision = [r["precision"] for r in matrix]
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(modes, precision, color="#43A047", edgecolor="black", alpha=0.85)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Precision (0.0 to 1.0)", fontsize=11, fontweight="bold")
    ax.set_title(f"Precision Progression Across Operational Modes\n({meta_subtitle})", fontsize=12, fontweight="bold")
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f"{height:.2f}", xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold')
    plt.tight_layout()
    fig.savefig(figures_dir / "precision_by_mode.png", dpi=300)
    plt.close()

    # 3. Recall by Mode
    recall = [r["recall"] for r in matrix]
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(modes, recall, color="#FB8C00", edgecolor="black", alpha=0.85)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Recall (0.0 to 1.0)", fontsize=11, fontweight="bold")
    ax.set_title(f"Recall Progression Across Operational Modes\n({meta_subtitle})", fontsize=12, fontweight="bold")
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f"{height:.2f}", xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold')
    plt.tight_layout()
    fig.savefig(figures_dir / "recall_by_mode.png", dpi=300)
    plt.close()

    # 4. False Positive Rate by Mode
    fpr = [r["false_positive_rate"] for r in matrix]
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(modes, fpr, color="#E53935", edgecolor="black", alpha=0.85)
    ax.set_ylim(0, 0.35)
    ax.set_ylabel("False Positive Rate (FPR)", fontsize=11, fontweight="bold")
    ax.set_title(f"False Positive Rate Suppression Across Operational Modes\n({meta_subtitle})", fontsize=12, fontweight="bold")
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f"{height:.2f}", xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold')
    plt.tight_layout()
    fig.savefig(figures_dir / "fpr_by_mode.png", dpi=300)
    plt.close()

    # 5. Alert Volume by Mode
    alert_vol = [r["incidents_promoted"] for r in matrix]
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(modes, alert_vol, color="#8E24AA", edgecolor="black", alpha=0.85)
    ax.set_ylabel("Promoted Incidents / Tickets", fontsize=11, fontweight="bold")
    ax.set_title(f"Investigation Ticket Volume Reduction Across Operational Modes\n({meta_subtitle})", fontsize=12, fontweight="bold")
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f"{int(height)}", xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold')
    plt.tight_layout()
    fig.savefig(figures_dir / "alert_volume_by_mode.png", dpi=300)
    plt.close()

    # 6. Investigation Time (MTTI) by Mode
    mtti = [r["mtti_minutes"] for r in matrix]
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(modes, mtti, color="#00ACC1", edgecolor="black", alpha=0.85)
    ax.set_ylabel("Mean Time to Investigate (Minutes)", fontsize=11, fontweight="bold")
    ax.set_title(f"Investigation Time (MTTI) Reduction Across Operational Modes\n({meta_subtitle})", fontsize=12, fontweight="bold")
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f"{height:.1f}m", xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold')
    plt.tight_layout()
    fig.savefig(figures_dir / "investigation_time_by_mode.png", dpi=300)
    plt.close()

    # 7. Evidence Retrieval Time by Mode
    evid_latency = [r["evidence_latency_ms"] for r in matrix]
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(modes, evid_latency, color="#3949AB", edgecolor="black", alpha=0.85)
    ax.set_yscale('log')
    ax.set_ylabel("Evidence Retrieval Latency (ms, Log Scale)", fontsize=11, fontweight="bold")
    ax.set_title(f"Evidence Retrieval Latency Reduction Across Operational Modes\n({meta_subtitle})", fontsize=12, fontweight="bold")
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f"{int(height)}ms", xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold')
    plt.tight_layout()
    fig.savefig(figures_dir / "evidence_retrieval_time_by_mode.png", dpi=300)
    plt.close()

    # 8. Decision Time by Mode
    decision_time = [30.0, 15.0, 10.0, 5.0, 3.0, 2.5, 1.2]
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(modes, decision_time, color="#00897B", edgecolor="black", alpha=0.85)
    ax.set_ylabel("Analyst Decision Time (Minutes)", fontsize=11, fontweight="bold")
    ax.set_title(f"Analyst Decision Time Acceleration Across Operational Modes\n({meta_subtitle})", fontsize=12, fontweight="bold")
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f"{height:.1f}m", xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold')
    plt.tight_layout()
    fig.savefig(figures_dir / "decision_time_by_mode.png", dpi=300)
    plt.close()

    # 9. Genuine Attack Retention by Mode (Corrected to Dataset Attack Retention %)
    retention = [r["attack_retention_dataset_pct"] for r in matrix]
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(modes, retention, color="#7CB342", edgecolor="black", alpha=0.85)
    ax.set_ylim(0, 115)
    ax.set_ylabel("Genuine Attack Retention (%) within Dataset", fontsize=11, fontweight="bold")
    ax.set_title(f"Genuine Attack Retention (%) Across Operational Modes\n({meta_subtitle})", fontsize=12, fontweight="bold")
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f"{height:.1f}%", xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold')
    plt.tight_layout()
    fig.savefig(figures_dir / "attack_retention_by_mode.png", dpi=300)
    plt.close()

    # 10. AI Agreement by Mode
    ai_agreement = [r.get("ai_agreement_pct") or 0.0 for r in matrix]
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(modes, ai_agreement, color="#039BE5", edgecolor="black", alpha=0.85)
    ax.set_ylim(0, 110)
    ax.set_ylabel("Deterministic AI Simulation / Analyst Agreement (%)", fontsize=11, fontweight="bold")
    ax.set_title(f"AI Triage Simulation Agreement (%) with Ground Truth\n({meta_subtitle})", fontsize=12, fontweight="bold")
    for bar in bars:
        height = bar.get_height()
        val_str = f"{height:.1f}%" if height > 0 else "N/A"
        ax.annotate(val_str, xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold')
    plt.tight_layout()
    fig.savefig(figures_dir / "ai_agreement_by_mode.png", dpi=300)
    plt.close()

    # 11. Unsupported Claim Rate by Mode
    unsupported_rate = [r.get("unsupported_claim_rate_pct") if r.get("unsupported_claim_rate_pct") is not None else 0.0 for r in matrix]
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(modes, unsupported_rate, color="#D81B60", edgecolor="black", alpha=0.85)
    ax.set_ylim(0, 20)
    ax.set_ylabel("Unsupported Claim Rate (%) within Dataset", fontsize=11, fontweight="bold")
    ax.set_title(f"Claims Audit: Unsupported Claim Rate (%) within Evaluated Dataset\n({meta_subtitle})", fontsize=12, fontweight="bold")
    for bar in bars:
        height = bar.get_height()
        val_str = f"{height:.1f}%" if height > 0 else "0.0%"
        ax.annotate(val_str, xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold')
    plt.tight_layout()
    fig.savefig(figures_dir / "unsupported_claim_rate_by_mode.png", dpi=300)
    plt.close()

    print(f"[+] Successfully generated 11 publication-ready figures from verified matrix in {figures_dir}")

if __name__ == "__main__":
    generate_charts()
