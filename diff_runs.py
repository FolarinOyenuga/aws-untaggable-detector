#!/usr/bin/env python3
"""
Compare two runs of the untaggable resource detection to identify changes.

Usage:
    python diff_runs.py output/api_taggable_resources.json output/api_taggable_resources_prev.json
    python diff_runs.py  # Uses current and previous runs from history/
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()

HISTORY_DIR = Path(__file__).parent / "history"
OUTPUT_DIR = Path(__file__).parent / "output"


def load_report(filepath: Path) -> dict:
    """Load a JSON report file."""
    with open(filepath) as f:
        return json.load(f)


def extract_untaggable_set(report: dict) -> set[tuple[str, str]]:
    """Extract set of (service, resource) tuples from report."""
    resources = set()
    for item in report.get("untaggable_resources", []):
        resources.add((item["service"], item["resource"]))
    return resources


def compare_reports(old_report: dict, new_report: dict) -> dict:
    """Compare two reports and return differences."""
    old_resources = extract_untaggable_set(old_report)
    new_resources = extract_untaggable_set(new_report)
    
    added = new_resources - old_resources
    removed = old_resources - new_resources
    unchanged = old_resources & new_resources
    
    old_summary = old_report.get("summary", {})
    new_summary = new_report.get("summary", {})
    
    return {
        "added": sorted(list(added)),
        "removed": sorted(list(removed)),
        "unchanged_count": len(unchanged),
        "summary_changes": {
            "total_services": {
                "old": old_summary.get("total_services", 0),
                "new": new_summary.get("total_services", 0),
            },
            "services_without_tagging_api": {
                "old": old_summary.get("services_without_tagging_api", 0),
                "new": new_summary.get("services_without_tagging_api", 0),
            },
            "total_untaggable_resources": {
                "old": old_summary.get("total_untaggable_resources", 0),
                "new": new_summary.get("total_untaggable_resources", 0),
            },
        }
    }


def save_to_history(report_path: Path) -> Path:
    """Save current report to history with timestamp."""
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    history_file = HISTORY_DIR / f"api_taggable_resources_{timestamp}.json"
    
    with open(report_path) as f:
        data = json.load(f)
    
    data["run_timestamp"] = timestamp
    
    with open(history_file, "w") as f:
        json.dump(data, f, indent=2)
    
    console.print(f"[green]Saved to history: {history_file}[/green]")
    return history_file


def get_latest_history_files() -> tuple[Path | None, Path | None]:
    """Get the two most recent history files."""
    if not HISTORY_DIR.exists():
        return None, None
    
    files = sorted(HISTORY_DIR.glob("api_taggable_resources_*.json"), reverse=True)
    
    if len(files) >= 2:
        return files[1], files[0]
    elif len(files) == 1:
        return None, files[0]
    return None, None


def display_diff(diff: dict) -> None:
    """Display the diff results."""
    console.print("\n[bold cyan]═══ DIFF RESULTS ═══[/bold cyan]\n")
    
    table = Table(title="Summary Changes")
    table.add_column("Metric", style="cyan")
    table.add_column("Previous", style="yellow")
    table.add_column("Current", style="green")
    table.add_column("Change", style="magenta")
    
    for metric, values in diff["summary_changes"].items():
        old_val = values["old"]
        new_val = values["new"]
        change = new_val - old_val
        change_str = f"+{change}" if change > 0 else str(change)
        table.add_row(metric.replace("_", " ").title(), str(old_val), str(new_val), change_str)
    
    console.print(table)
    
    console.print(f"\n[bold]Unchanged resources: {diff['unchanged_count']}[/bold]")
    
    if diff["added"]:
        console.print(f"\n[bold green]ADDED ({len(diff['added'])}):[/bold green]")
        for service, resource in diff["added"][:20]:
            console.print(f"  + {service}: {resource}")
        if len(diff["added"]) > 20:
            console.print(f"  ... and {len(diff['added']) - 20} more")
    
    if diff["removed"]:
        console.print(f"\n[bold red]REMOVED ({len(diff['removed'])}):[/bold red]")
        for service, resource in diff["removed"][:20]:
            console.print(f"  - {service}: {resource}")
        if len(diff["removed"]) > 20:
            console.print(f"  ... and {len(diff['removed']) - 20} more")
    
    if not diff["added"] and not diff["removed"]:
        console.print("\n[bold green]No changes detected![/bold green]")


def main():
    if len(sys.argv) == 3:
        old_file = Path(sys.argv[1])
        new_file = Path(sys.argv[2])
    elif len(sys.argv) == 1:
        old_file, new_file = get_latest_history_files()
        if not old_file or not new_file:
            console.print("[yellow]Not enough history files for comparison.[/yellow]")
            console.print("Run the detector twice to generate history, or provide two files as arguments.")
            return
    else:
        console.print("Usage: python diff_runs.py [old_file.json] [new_file.json]")
        return
    
    if not old_file.exists():
        console.print(f"[red]File not found: {old_file}[/red]")
        return
    if not new_file.exists():
        console.print(f"[red]File not found: {new_file}[/red]")
        return
    
    console.print(f"[blue]Comparing:[/blue]")
    console.print(f"  Old: {old_file}")
    console.print(f"  New: {new_file}")
    
    old_report = load_report(old_file)
    new_report = load_report(new_file)
    
    diff = compare_reports(old_report, new_report)
    display_diff(diff)
    
    diff_output = OUTPUT_DIR / "diff_report.json"
    with open(diff_output, "w") as f:
        json.dump(diff, f, indent=2, default=str)
    console.print(f"\n[green]Diff report saved to {diff_output}[/green]")


if __name__ == "__main__":
    main()
