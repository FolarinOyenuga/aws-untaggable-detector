#!/usr/bin/env python3
"""
[PRIMARY/AUTHORITATIVE] Detect which AWS resources support tagging at the API level.

This is the authoritative source for untaggable resource detection.
Use this script for comprehensive analysis.

Source of Truth: IAM Service Authorization Reference
Methodology:
- A resource is TAGGABLE if it has aws:ResourceTag/${TagKey} condition key
  in the Resource types table, OR is in scope of TagResource/CreateTags action
- A resource is UNTAGGABLE only if it has NEITHER of these indicators

This is the definitive API-level answer regardless of creation method.

Related scripts:
- detect_service_level.py [SECONDARY] - Quick service-level check
- cfn_to_iam_mapper.py [SUPPLEMENTARY] - CloudFormation resource mapping
"""

import json
import re
import time
from datetime import datetime
from bs4 import BeautifulSoup
from pathlib import Path
from rich.console import Console
from rich.table import Table
from concurrent.futures import ThreadPoolExecutor, as_completed
from cache_config import get_cached_session
from exceptions import AWSDocStructureError

console = Console()
session = get_cached_session()

MIN_EXPECTED_SERVICES = 400
MAX_RETRIES = 3
RETRY_DELAY = 2

SERVICE_AUTH_REF_BASE = "https://docs.aws.amazon.com/service-authorization/latest/reference"
SERVICE_AUTH_REF_TOC = f"{SERVICE_AUTH_REF_BASE}/reference_policies_actions-resources-contextkeys.html"


def get_all_services() -> list[dict]:
    """Fetch all AWS services from IAM Authorization Reference."""
    console.print("[blue]Fetching AWS services from IAM Authorization Reference...[/blue]")
    
    response = session.get(SERVICE_AUTH_REF_TOC, timeout=30)
    response.raise_for_status()
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
    
    if len(services) < MIN_EXPECTED_SERVICES:
        raise AWSDocStructureError(
            f"Expected at least {MIN_EXPECTED_SERVICES} services, found {len(services)}. "
            "AWS documentation structure may have changed."
        )
    
    return services


def extract_service_prefix(soup: BeautifulSoup) -> str:
    """Extract the service prefix (e.g., 'ec2', 'cognito-idp') from the page."""
    text = soup.get_text()
    match = re.search(r'service prefix[:\s]+([a-z0-9-]+)', text.lower())
    if match:
        return match.group(1)
    return ""


def extract_resource_types_with_tagging_info(soup: BeautifulSoup) -> dict:
    """Extract all resource types and identify which have aws:ResourceTag condition keys.
    
    The presence of aws:ResourceTag/${TagKey} condition key is the authoritative
    indicator that a resource supports tagging, regardless of TagResource action scope.
    """
    resources = {}
    
    resource_section = None
    for heading in soup.find_all(["h2", "h3"]):
        if "resource type" in heading.get_text(strip=True).lower():
            resource_section = heading
            break
    
    if not resource_section:
        return {"all_resources": [], "resources_with_tag_condition": []}
    
    table = resource_section.find_next("table")
    if not table:
        return {"all_resources": [], "resources_with_tag_condition": []}
    
    headers = [th.get_text(strip=True).lower() for th in table.find_all("th")]
    if not any("arn" in h for h in headers):
        return {"all_resources": [], "resources_with_tag_condition": []}
    
    condition_col = next((i for i, h in enumerate(headers) if "condition" in h), -1)
    
    all_resources = []
    resources_with_tag_condition = []
    
    for row in table.find_all("tr")[1:]:
        cells = row.find_all("td")
        if cells:
            resource_name = cells[0].get_text(strip=True).lower()
            resource_name = resource_name.replace("*", "").replace("required", "").strip()
            if resource_name and resource_name not in ["", "-"]:
                all_resources.append(resource_name)
                
                if condition_col >= 0 and len(cells) > condition_col:
                    condition_text = cells[condition_col].get_text(strip=True).lower()
                    if "aws:resourcetag" in condition_text:
                        resources_with_tag_condition.append(resource_name)
    
    return {
        "all_resources": all_resources,
        "resources_with_tag_condition": resources_with_tag_condition,
    }


def extract_tagging_actions_and_resources(soup: BeautifulSoup) -> dict:
    """Extract tagging actions and which resources they apply to."""
    tagging_actions = []
    taggable_resources = set()
    
    actions_section = None
    for heading in soup.find_all(["h2", "h3"]):
        heading_text = heading.get_text(strip=True).lower()
        if "actions defined" in heading_text or heading_text == "actions":
            actions_section = heading
            break
    
    if not actions_section:
        return {"tagging_actions": [], "taggable_resources": []}
    
    table = actions_section.find_next("table")
    if not table:
        return {"tagging_actions": [], "taggable_resources": []}
    
    headers = [th.get_text(strip=True).lower() for th in table.find_all("th")]
    action_col = next((i for i, h in enumerate(headers) if "action" in h), 0)
    resource_col = next((i for i, h in enumerate(headers) if "resource" in h), -1)
    
    if resource_col == -1:
        return {"tagging_actions": [], "taggable_resources": []}
    
    for row in table.find_all("tr")[1:]:
        cells = row.find_all("td")
        if len(cells) > max(action_col, resource_col):
            action_cell = cells[action_col]
            resource_cell = cells[resource_col]
            
            action_link = action_cell.find("a")
            action_text = (action_link.get_text(strip=True) if action_link else action_cell.get_text(strip=True)).lower()
            
            is_tagging = any(pattern in action_text for pattern in [
                "tagresource", "untagresource", 
                "createtags", "deletetags",
                "addtags", "removetags"
            ])
            
            if is_tagging:
                tagging_actions.append(action_text)
                for link in resource_cell.find_all("a"):
                    res = link.get_text(strip=True).lower()
                    res = res.replace("*", "").replace("required", "").strip()
                    if res and res not in ["", "-", "*"]:
                        taggable_resources.add(res)
    
    return {
        "tagging_actions": list(set(tagging_actions)),
        "taggable_resources": list(taggable_resources),
    }


def fetch_with_retry(url: str, max_retries: int = MAX_RETRIES) -> str:
    """Fetch URL with exponential backoff retry."""
    last_error = None
    for attempt in range(max_retries):
        try:
            response = session.get(url, timeout=30)
            response.raise_for_status()
            return response.text
        except Exception as e:
            last_error = e
            if attempt < max_retries - 1:
                delay = RETRY_DELAY * (2 ** attempt)
                time.sleep(delay)
    raise last_error


def analyze_service(service: dict) -> dict:
    """Analyze a single service for resource-level tagging support.
    
    A resource is considered TAGGABLE if:
    1. It has aws:ResourceTag/${TagKey} condition key in the Resource types table, OR
    2. It's listed in the scope of a TagResource/CreateTags/AddTags action
    
    A resource is UNTAGGABLE only if it has NEITHER of these indicators.
    """
    try:
        html = fetch_with_retry(service["url"])
        soup = BeautifulSoup(html, "lxml")
        
        resource_info = extract_resource_types_with_tagging_info(soup)
        tagging_info = extract_tagging_actions_and_resources(soup)
        
        all_resources = set(resource_info["all_resources"])
        resources_with_tag_condition = set(resource_info["resources_with_tag_condition"])
        resources_in_tag_action_scope = set(tagging_info["taggable_resources"])
        
        taggable = resources_with_tag_condition | resources_in_tag_action_scope
        untaggable = list(all_resources - taggable)
        
        has_tagging = len(tagging_info["tagging_actions"]) > 0 or len(resources_with_tag_condition) > 0
        
        return {
            "name": service["name"],
            "url": service["url"],
            "has_tagging_api": has_tagging,
            "all_resources": list(all_resources),
            "taggable_resources": list(taggable),
            "untaggable_resources": untaggable,
            "tagging_actions": tagging_info["tagging_actions"],
            "resources_with_tag_condition": list(resources_with_tag_condition),
        }
    except Exception as e:
        return {
            "name": service["name"],
            "url": service["url"],
            "error": str(e),
        }


def main():
    console.print("[bold]AWS Resource-Level Tagging Detection (API Source of Truth)[/bold]")
    console.print("[dim]Parsing IAM Service Authorization Reference for resource-level tagging support[/dim]\n")
    
    services = get_all_services()
    console.print(f"[green]Found {len(services)} AWS services[/green]")
    
    results = []
    
    console.print("[blue]Analyzing services for resource-level tagging...[/blue]")
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(analyze_service, svc): svc for svc in services}
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 50 == 0:
                console.print(f"  Progress: {completed}/{len(services)}")
            
            result = future.result()
            results.append(result)
    
    no_tagging_api = []
    has_tagging_api = []
    mixed_services = []
    errors = []
    
    for r in results:
        if r.get("error"):
            errors.append(r)
        elif not r.get("has_tagging_api"):
            no_tagging_api.append(r)
        else:
            has_tagging_api.append(r)
            if r.get("untaggable_resources"):
                mixed_services.append(r)
    
    if errors:
        console.print(f"\n[bold red]WARNING: {len(errors)} services failed to parse[/bold red]")
        for err in errors[:5]:
            console.print(f"  - {err['name']}: {err.get('error', 'Unknown error')}")
        if len(errors) > 5:
            console.print(f"  ... and {len(errors) - 5} more")
    
    console.print("\n[bold cyan]═══ RESULTS ═══[/bold cyan]\n")
    
    table = Table(title="API-Level Tagging Analysis")
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="magenta")
    
    table.add_row("Services WITHOUT tagging API", str(len(no_tagging_api)))
    table.add_row("Services WITH tagging API", str(len(has_tagging_api)))
    table.add_row("Mixed services (some resources untaggable)", str(len(mixed_services)))
    table.add_row("Errors", str(len(errors)))
    
    console.print(table)
    
    if mixed_services:
        console.print("\n[bold yellow]MIXED SERVICES (have both taggable and untaggable resources):[/bold yellow]\n")
        for svc in sorted(mixed_services, key=lambda x: x["name"]):
            console.print(f"[cyan]{svc['name']}[/cyan]")
            console.print(f"  Taggable: {', '.join(svc['taggable_resources'][:5])}{'...' if len(svc['taggable_resources']) > 5 else ''}")
            console.print(f"  [red]Untaggable: {', '.join(svc['untaggable_resources'][:5])}{'...' if len(svc['untaggable_resources']) > 5 else ''}[/red]")
    
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    all_untaggable = []
    
    for svc in no_tagging_api:
        for res in svc.get("all_resources", []):
            all_untaggable.append({
                "resource": res,
                "service": svc["name"],
                "reason": "service_no_tagging_api"
            })
    
    for svc in mixed_services:
        for res in svc.get("untaggable_resources", []):
            all_untaggable.append({
                "resource": res,
                "service": svc["name"],
                "reason": "resource_not_in_tag_action_scope"
            })
    
    report = {
        "summary": {
            "total_services": len(services),
            "services_without_tagging_api": len(no_tagging_api),
            "services_with_tagging_api": len(has_tagging_api),
            "mixed_services": len(mixed_services),
            "total_untaggable_resources": len(all_untaggable),
        },
        "untaggable_resources": all_untaggable,
        "services_without_tagging_api": [s["name"] for s in no_tagging_api],
        "mixed_services_detail": [{
            "name": s["name"],
            "taggable": s["taggable_resources"],
            "untaggable": s["untaggable_resources"],
        } for s in mixed_services],
    }
    
    output_file = output_dir / "api_taggable_resources.json"
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    
    history_dir = Path(__file__).parent / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    history_file = history_dir / f"api_taggable_resources_{timestamp}.json"
    report["run_timestamp"] = timestamp
    with open(history_file, "w") as f:
        json.dump(report, f, indent=2)
    
    console.print(f"\n[green]Report saved to {output_file}[/green]")
    console.print(f"[green]History saved to {history_file}[/green]")
    console.print(f"\n[bold]Total untaggable resources identified: {len(all_untaggable)}[/bold]")
    console.print("[dim]Run 'python diff_runs.py' to compare with previous runs[/dim]")


if __name__ == "__main__":
    main()
