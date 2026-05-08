from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
CRITERION_DIR = ROOT / "target" / "criterion"
OUTPUT_DIR = ROOT / "bench_results"
OUTPUT_SVG = OUTPUT_DIR / "benchmark_flows.svg"
OUTPUT_PNG = OUTPUT_DIR / "benchmark_flows.png"


def load_estimates() -> list[tuple[str, float]]:
    rows: list[tuple[str, float]] = []
    for path in sorted(CRITERION_DIR.glob("**/new/estimates.json")):
        benchmark_path = path.with_name("benchmark.json")
        benchmark = json.loads(benchmark_path.read_text())
        estimate = json.loads(path.read_text())
        label = benchmark["full_id"]
        mean_ns = float(estimate["mean"]["point_estimate"])
        rows.append((label, mean_ns / 1_000.0))
    return rows


def main() -> None:
    rows = load_estimates()
    primitive_order = [
        "commitments/keygen_commitment",
        "commitments/nonce_commitment",
        "commitments/sign",
        "commitments/verify",
    ]
    flow_order = ["keygen_simulation_n3", "presign_sign_round_trip_n3"]

    primitive_rows = [row for row in rows if row[0] in primitive_order]
    primitive_rows.sort(key=lambda row: primitive_order.index(row[0]))
    flow_rows = [row for row in rows if row[0] in flow_order]
    flow_rows.sort(key=lambda row: flow_order.index(row[0]))

    fig, axes = plt.subplots(2, 1, figsize=(10.5, 6.5), constrained_layout=True)
    fig.suptitle("DKLs23 Lockness Benchmarks", fontsize=16, fontweight="bold")

    def bar_panel(ax, data, title, color):
        labels = [label.replace("commitments/", "") for label, _ in data]
        values = [value for _, value in data]
        positions = list(range(len(data)))
        bars = ax.barh(positions, values, color=color, alpha=0.88)
        ax.set_yticks(positions, labels)
        ax.invert_yaxis()
        ax.set_xlabel("Mean time (µs)")
        ax.set_title(title, fontsize=12, loc="left")
        ax.grid(axis="x", linestyle="--", alpha=0.25)
        ax.set_axisbelow(True)
        for bar, value in zip(bars, values):
            ax.text(
                bar.get_width() + max(values) * 0.01,
                bar.get_y() + bar.get_height() / 2,
                f"{value:.3f} µs",
                va="center",
                ha="left",
                fontsize=9,
            )

    bar_panel(axes[0], primitive_rows, "Primitive operations", "#3b82f6")
    bar_panel(axes[1], flow_rows, "End-to-end protocol flows", "#10b981")

    axes[1].set_yticklabels([
        "keygen_simulation_n3",
        "presign_sign_round_trip_n3",
    ])

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUTPUT_SVG, format="svg")
    fig.savefig(OUTPUT_PNG, format="png", dpi=200)
    plt.close(fig)
    print(f"wrote {OUTPUT_SVG}")
    print(f"wrote {OUTPUT_PNG}")


if __name__ == "__main__":
    main()
