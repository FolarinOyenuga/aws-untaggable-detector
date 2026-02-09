#!/usr/bin/env python3
"""
Resource Groups Tagging API Analyzer for Detecting Untaggable Resources

This script uses the AWS Resource Groups Tagging API to identify which
services/resources support tagging through this unified API.

The Resource Groups Tagging API provides:
- get_resources: List all tagged resources
- get_tag_keys: List all tag keys in use
- get_tag_values: List values for a specific tag key
- tag_resources: Add tags to resources
- untag_resources: Remove tags from resources

Reference:
https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/Welcome.html
"""

import json
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from pathlib import Path
from rich.console import Console
from rich.table import Table
from collections import defaultdict

console = Console()

# Known resource type prefixes from AWS documentation
# This list can be updated as AWS adds support for more services
KNOWN_TAGGING_API_SUPPORTED_SERVICES = [
    "acm",
    "apigateway",
    "appmesh",
    "athena",
    "autoscaling",
    "cloudformation",
    "cloudfront",
    "cloudwatch",
    "codebuild",
    "codecommit",
    "codepipeline",
    "cognito",
    "config",
    "dynamodb",
    "ec2",
    "ecr",
    "ecs",
    "efs",
    "eks",
    "elasticache",
    "elasticbeanstalk",
    "elasticloadbalancing",
    "es",  # Elasticsearch/OpenSearch
    "events",
    "firehose",
    "glacier",
    "glue",
    "iam",
    "kinesis",
    "kms",
    "lambda",
    "logs",
    "rds",
    "redshift",
    "route53",
    "s3",
    "sagemaker",
    "secretsmanager",
    "sns",
    "sqs",
    "ssm",
    "states",  # Step Functions
    "waf",
    "wafv2",
]


def get_tagging_api_client(region: str = "eu-west-2"):
    """Create a Resource Groups Tagging API client."""
    try:
        return boto3.client("resourcegroupstaggingapi", region_name=region)
    except NoCredentialsError:
        console.print("[red]AWS credentials not found. Please configure AWS CLI.[/red]")
        raise


def discover_tagged_resource_types(client) -> dict:
    """
    Use get_resources to discover what resource types exist with tags.
    
    Returns:
        Dict mapping service prefixes to list of resource types
    """
    console.print("[blue]Discovering tagged resources in account...[/blue]")
    
    resource_types = defaultdict(set)
    
    try:
        paginator = client.get_paginator("get_resources")
        
        for page in paginator.paginate():
            for resource in page.get("ResourceTagMappingList", []):
                arn = resource.get("ResourceARN", "")
                # Parse ARN to extract service and resource type
                # ARN format: arn:aws:service:region:account:resource-type/resource-id
                parts = arn.split(":")
                if len(parts) >= 6:
                    service = parts[2]
                    resource_type = parts[5].split("/")[0] if "/" in parts[5] else parts[5]
                    resource_types[service].add(resource_type)
        
        return {k: sorted(list(v)) for k, v in resource_types.items()}
    
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "PaginationTokenExpiredException":
            console.print(f"[yellow]Pagination token expired (large account). Returning partial results.[/yellow]")
            return {k: sorted(list(v)) for k, v in resource_types.items()}
        console.print(f"[red]Error accessing Tagging API: {error_code}[/red]")
        console.print(f"[yellow]Message: {e.response.get('Error', {}).get('Message', '')}[/yellow]")
        return {}


def get_tag_statistics(client) -> dict:
    """Get statistics about tags in the account."""
    console.print("[blue]Gathering tag statistics...[/blue]")
    
    stats = {
        "total_tag_keys": 0,
        "tag_keys": [],
    }
    
    try:
        paginator = client.get_paginator("get_tag_keys")
        
        for page in paginator.paginate():
            keys = page.get("TagKeys", [])
            stats["tag_keys"].extend(keys)
        
        stats["total_tag_keys"] = len(stats["tag_keys"])
        return stats
    
    except ClientError as e:
        console.print(f"[yellow]Could not get tag keys: {e}[/yellow]")
        return stats


def check_service_tagging_support(client, service_prefix: str) -> bool:
    """
    Check if a service supports the Resource Groups Tagging API
    by attempting to query for its resources.
    """
    try:
        response = client.get_resources(
            ResourceTypeFilters=[f"{service_prefix}:*"],
            ResourcesPerPage=1,
        )
        # If we get a response (even empty), the service is supported
        return True
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "InvalidParameterException":
            # Invalid resource type filter means not supported
            return False
        # Other errors might indicate permission issues, not lack of support
        return None


def analyze_services(client) -> tuple[list, list, list]:
    """
    Analyze known services for Tagging API support.
    
    Returns:
        Tuple of (supported, unsupported, unknown)
    """
    console.print("[blue]Checking known services for Tagging API support...[/blue]")
    
    supported = []
    unsupported = []
    unknown = []
    
    for service in KNOWN_TAGGING_API_SUPPORTED_SERVICES:
        result = check_service_tagging_support(client, service)
        if result is True:
            supported.append(service)
        elif result is False:
            unsupported.append(service)
        else:
            unknown.append(service)
    
    return supported, unsupported, unknown


def generate_report(
    discovered_types: dict,
    tag_stats: dict,
    supported: list,
    unsupported: list,
    unknown: list,
    output_dir: Path,
) -> None:
    """Generate reports and display summary."""
    
    # Display summary table
    table = Table(title="Resource Groups Tagging API Analysis")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    
    table.add_row("Services discovered in account", str(len(discovered_types)))
    table.add_row("Tag keys in use", str(tag_stats.get("total_tag_keys", "N/A")))
    table.add_row("Services confirmed supported", str(len(supported)))
    table.add_row("Services not supported", str(len(unsupported)))
    table.add_row("Services with unknown status", str(len(unknown)))
    
    console.print(table)
    
    if discovered_types:
        console.print("\n[bold green]Discovered Resource Types by Service:[/bold green]")
        for service in sorted(discovered_types.keys()):
            types = discovered_types[service]
            console.print(f"\n[cyan]{service}[/cyan] ({len(types)} types):")
            for t in types:
                console.print(f"  - {t}")
    
    if unsupported:
        console.print("\n[bold red]Services NOT Supported by Tagging API:[/bold red]")
        for svc in sorted(unsupported):
            console.print(f"  - {svc}")
    
    # Save to JSON
    output_dir.mkdir(parents=True, exist_ok=True)
    
    report = {
        "summary": {
            "discovered_services": len(discovered_types),
            "tag_keys_in_use": tag_stats.get("total_tag_keys", 0),
            "confirmed_supported": len(supported),
            "not_supported": len(unsupported),
            "unknown_status": len(unknown),
        },
        "discovered_resource_types": discovered_types,
        "tag_keys": tag_stats.get("tag_keys", []),
        "supported_services": supported,
        "unsupported_services": unsupported,
        "unknown_services": unknown,
    }
    
    output_file = output_dir / "rgtapi_analysis.json"
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    
    console.print(f"\n[green]Report saved to {output_file}[/green]")


def main():
    """Main entry point."""
    console.print("[bold]Resource Groups Tagging API Analysis[/bold]\n")
    
    try:
        client = get_tagging_api_client()
    except NoCredentialsError:
        console.print("[red]Please configure AWS credentials and try again.[/red]")
        return
    
    # Discover what's tagged in the account
    discovered_types = discover_tagged_resource_types(client)
    
    # Get tag statistics
    tag_stats = get_tag_statistics(client)
    
    # Check known services for support
    supported, unsupported, unknown = analyze_services(client)
    
    # Generate report
    output_dir = Path(__file__).parent.parent / "output"
    generate_report(
        discovered_types,
        tag_stats,
        supported,
        unsupported,
        unknown,
        output_dir,
    )


if __name__ == "__main__":
    main()
