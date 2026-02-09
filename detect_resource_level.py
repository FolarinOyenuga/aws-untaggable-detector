#!/usr/bin/env python3
"""
[SUPPLEMENTARY] Map CloudFormation resource types to tagging status.

This script maps CFN resource types to their tagging support status by
cross-referencing with IAM service data. Useful for IaC teams.

For authoritative resource-level detection, use detect_api_taggable.py instead.

Related scripts:
- detect_api_taggable.py [PRIMARY] - Authoritative resource-level detection
- detect_service_level.py [SECONDARY] - Quick service-level check
"""

import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from cache_config import get_cached_session
from service_mapping import CFN_TO_IAM_SERVICE, normalize_for_fuzzy_match

console = Console()
session = get_cached_session()

CFN_SPEC_URL = "https://d1uauaxba7bl26.cloudfront.net/latest/gzip/CloudFormationResourceSpecification.json"


def load_service_level_data(output_dir: Path) -> dict:
    """Load the service-level untaggable data."""
    service_file = output_dir / "service_level_untaggable.json"
    if service_file.exists():
        with open(service_file) as f:
            return json.load(f)
    return {"untaggable_services": [], "taggable_services": []}


def get_cfn_resources() -> dict:
    """Get all CFN resource types grouped by service."""
    console.print("[blue]Fetching CloudFormation resource types...[/blue]")
    
    spec = session.get(CFN_SPEC_URL, timeout=30).json()
    resource_types = spec.get("ResourceTypes", {})
    
    by_service = {}
    for resource_type in resource_types.keys():
        parts = resource_type.split("::")
        if len(parts) >= 3:
            service = parts[1].lower()
            if service not in by_service:
                by_service[service] = []
            by_service[service].append(resource_type)
    
    return by_service


def match_service(cfn_prefix: str, service_list: list[str]) -> str | None:
    """Match a CFN prefix to an IAM service name using verified mapping first, then exact fuzzy fallback."""
    cfn_lower = cfn_prefix.lower()
    
    iam_name = CFN_TO_IAM_SERVICE.get(cfn_lower)
    if iam_name and iam_name in service_list:
        return iam_name
    
    cfn_norm = normalize_for_fuzzy_match(cfn_lower)
    for svc in service_list:
        if normalize_for_fuzzy_match(svc) == cfn_norm:
            return svc
    
    return None


def identify_resource_level_untaggables(
    cfn_resources: dict,
    service_data: dict,
) -> dict:
    """Identify resources in untaggable vs taggable services using verified mapping."""
    taggable_services = service_data.get("taggable_services", [])
    untaggable_services = service_data.get("untaggable_services", [])
    
    results = {
        "in_taggable_services": {},
        "in_untaggable_services": {},
        "unknown_services": {},
    }
    
    for service, resources in cfn_resources.items():
        matched_taggable = match_service(service, taggable_services)
        matched_untaggable = match_service(service, untaggable_services)
        
        if matched_taggable and not matched_untaggable:
            results["in_taggable_services"][service] = {
                "matched_service": matched_taggable,
                "resources": resources,
            }
        elif matched_untaggable:
            results["in_untaggable_services"][service] = {
                "matched_service": matched_untaggable,
                "resources": resources,
            }
        else:
            results["unknown_services"][service] = {
                "resources": resources,
            }
    
    return results


def generate_report(results: dict, output_dir: Path) -> None:
    """Generate the resource-level report."""
    
    console.print("\n[bold cyan]═══ RESOURCE-LEVEL ANALYSIS ═══[/bold cyan]\n")
    
    taggable_svc_resources = sum(
        len(v["resources"]) for v in results["in_taggable_services"].values()
    )
    untaggable_svc_resources = sum(
        len(v["resources"]) for v in results["in_untaggable_services"].values()
    )
    unknown_resources = sum(
        len(v["resources"]) for v in results["unknown_services"].values()
    )
    
    table = Table(title="Resource Distribution")
    table.add_column("Category", style="cyan")
    table.add_column("Services", style="magenta")
    table.add_column("Resources", style="green")
    
    table.add_row(
        "In taggable services",
        str(len(results["in_taggable_services"])),
        str(taggable_svc_resources),
    )
    table.add_row(
        "In untaggable services",
        str(len(results["in_untaggable_services"])),
        str(untaggable_svc_resources),
    )
    table.add_row(
        "Unknown services",
        str(len(results["unknown_services"])),
        str(unknown_resources),
    )
    
    console.print(table)
    
    console.print("\n[bold red]RESOURCES IN UNTAGGABLE SERVICES[/bold red]")
    console.print("[dim]All resources in these services cannot be tagged[/dim]\n")
    
    all_untaggable_resources = []
    for service, data in sorted(results["in_untaggable_services"].items()):
        console.print(f"[yellow]{service}[/yellow] ({data['matched_service']})")
        for r in data["resources"]:
            console.print(f"  - {r}")
            all_untaggable_resources.append(r)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    report = {
        "summary": {
            "services_with_tagging_api": len(results["in_taggable_services"]),
            "resources_in_taggable_services": taggable_svc_resources,
            "services_without_tagging_api": len(results["in_untaggable_services"]),
            "resources_in_untaggable_services": untaggable_svc_resources,
            "unknown_services": len(results["unknown_services"]),
        },
        "untaggable_resources": sorted(all_untaggable_resources),
        "resources_needing_verification": {
            service: data["resources"]
            for service, data in results["in_taggable_services"].items()
        },
        "details": results,
    }
    
    output_file = output_dir / "resource_level_analysis.json"
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    
    console.print(f"\n[green]Report saved to {output_file}[/green]")
    
    console.print(f"\n[bold]Total resources in untaggable services: {len(all_untaggable_resources)}[/bold]")
    console.print("\n[yellow]Note: Resources in taggable services need manual verification[/yellow]")
    console.print("[yellow]to determine which specific resources don't support tagging.[/yellow]")


def main():
    console.print("[bold]Resource-Level Untaggable Detection[/bold]\n")
    
    output_dir = Path(__file__).parent / "output"
    
    service_data = load_service_level_data(output_dir)
    
    if not service_data.get("untaggable_services"):
        console.print("[red]Run detect_service_level.py first to generate service data[/red]")
        return
    
    console.print(f"[green]Loaded {len(service_data['taggable_services'])} taggable services[/green]")
    console.print(f"[green]Loaded {len(service_data['untaggable_services'])} untaggable services[/green]")
    
    cfn_resources = get_cfn_resources()
    total_resources = sum(len(r) for r in cfn_resources.values())
    console.print(f"[green]Found {total_resources} resource types across {len(cfn_resources)} services[/green]")
    
    results = identify_resource_level_untaggables(cfn_resources, service_data)
    generate_report(results, output_dir)


if __name__ == "__main__":
    main()
