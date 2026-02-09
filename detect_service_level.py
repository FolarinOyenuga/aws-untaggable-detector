#!/usr/bin/env python3
"""
Identify AWS services that DO NOT support tagging at the API level.

This is the source of truth - if a service has no tagging API actions,
it cannot be tagged regardless of how resources are created (CFN, Terraform, ClickOps).

Source: IAM Service Authorization Reference
"""

import json
from bs4 import BeautifulSoup
from pathlib import Path
from rich.console import Console
from rich.table import Table
from cache_config import get_cached_session

console = Console()
session = get_cached_session()

SERVICE_AUTH_REF_BASE = "https://docs.aws.amazon.com/service-authorization/latest/reference"
SERVICE_AUTH_REF_TOC = f"{SERVICE_AUTH_REF_BASE}/reference_policies_actions-resources-contextkeys.html"


def get_all_services() -> list[dict]:
    """Fetch all AWS services from IAM Authorization Reference."""
    console.print("[blue]Fetching AWS services from IAM Authorization Reference...[/blue]")
    
    response = session.get(SERVICE_AUTH_REF_TOC, timeout=30)
    soup = BeautifulSoup(response.text, "lxml")
    
    services = []
    for link in soup.find_all("a", href=True):
        href = link.get("href", "")
        if "list_" in href and href.endswith(".html"):
            service_name = link.get_text(strip=True)
            clean_href = href.lstrip("./")
            services.append({
                "name": service_name,
                "url": f"{SERVICE_AUTH_REF_BASE}/{clean_href}",
            })
    
    return services


def check_tagging_support(service_url: str) -> dict:
    """Check if a service has tagging API actions."""
    try:
        response = session.get(service_url, timeout=15)
        page_text = response.text.lower()
        found_actions = []
        
        if "tagresource" in page_text:
            found_actions.append("TagResource")
        if "untagresource" in page_text:
            found_actions.append("UntagResource")
        if "createtags" in page_text:
            found_actions.append("CreateTags")
        if "deletetags" in page_text:
            found_actions.append("DeleteTags")
        if "addtags" in page_text and "addtagsto" in page_text:
            found_actions.append("AddTags*")
        if "removetags" in page_text:
            found_actions.append("RemoveTags*")
        
        can_tag = any(a in ["TagResource", "CreateTags", "AddTags*"] for a in found_actions)
        can_untag = any(a in ["UntagResource", "DeleteTags", "RemoveTags*"] for a in found_actions)
        
        return {
            "has_tagging": can_tag and can_untag,
            "can_tag_only": can_tag and not can_untag,
            "tagging_actions": found_actions,
        }
    except Exception as e:
        return {
            "has_tagging": None,
            "error": str(e),
            "tagging_actions": [],
        }


def main():
    console.print("[bold]AWS Services Without Tagging Support (API Level)[/bold]")
    console.print("[dim]Source of truth for SCP policies - applies to all creation methods[/dim]\n")
    
    services = get_all_services()
    console.print(f"[green]Found {len(services)} AWS services[/green]")
    
    taggable = []
    untaggable = []
    errors = []
    
    console.print("[blue]Analyzing all services for tagging API support...[/blue]")
    
    total = len(services)
    for i, service in enumerate(services, 1):
        if i % 25 == 0:
            console.print(f"  Progress: {i}/{total}")
        
        result = check_tagging_support(service["url"])
        service["tagging_info"] = result
        
        if result.get("error"):
            errors.append(service)
        elif result["has_tagging"]:
            taggable.append(service)
        else:
            untaggable.append(service)
    
    console.print("\n[bold cyan]═══ RESULTS ═══[/bold cyan]\n")
    
    table = Table(title="API-Level Tagging Support")
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="magenta")
    
    table.add_row("Services WITH tagging API", str(len(taggable)))
    table.add_row("Services WITHOUT tagging API", str(len(untaggable)))
    table.add_row("Errors", str(len(errors)))
    
    console.print(table)
    
    console.print(f"\n[bold red]AWS SERVICES THAT DO NOT SUPPORT TAGGING ({len(untaggable)}):[/bold red]")
    console.print("[dim]These cannot be tagged via ANY method - CFN, Terraform, Console, or CLI[/dim]\n")
    
    for svc in sorted(untaggable, key=lambda x: x["name"]):
        console.print(f"  - {svc['name']}")
    
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    report = {
        "summary": {
            "total_services": len(services),
            "taggable_services": len(taggable),
            "untaggable_services": len(untaggable),
            "errors": len(errors),
        },
        "untaggable_services": [s["name"] for s in sorted(untaggable, key=lambda x: x["name"])],
        "taggable_services": [s["name"] for s in sorted(taggable, key=lambda x: x["name"])],
        "detailed": {
            "untaggable": [{
                "name": s["name"],
                "url": s["url"],
            } for s in untaggable],
            "taggable": [{
                "name": s["name"],
                "tagging_actions": s["tagging_info"]["tagging_actions"],
            } for s in taggable],
        }
    }
    
    output_file = output_dir / "service_level_untaggable.json"
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    
    console.print(f"\n[green]Report saved to {output_file}[/green]")
    
    console.print(f"\n[bold]BOTTOM LINE: {len(untaggable)} AWS services have no tagging support at the API level[/bold]")


if __name__ == "__main__":
    main()
