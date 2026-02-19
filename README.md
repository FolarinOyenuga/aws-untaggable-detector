# AWS Untaggable Resources Detector

## The Problem

**Tagging is critical for AWS cost allocation, compliance, and resource management.** But not all AWS resources support tagging and AWS doesn't provide a single list of what can't be tagged.

This creates real problems:
- **SCP policies fail**: when they enforce tags on untaggable resources
- **Cost allocation gaps**: untagged resources can't be attributed to teams/projects
- **Compliance blind spots**: you can't enforce what you can't tag
- **Manual maintenance hell**: keeping track of 534 untaggable resources across 461 services

## The Solution

This tool automatically detects all AWS resources that cannot be tagged by parsing the authoritative source: the **IAM Service Authorization Reference**.

### Methodology

A resource is considered **taggable** if:
- It has `aws:ResourceTag/${TagKey}` condition key in the Resource types table, OR
- It's in scope of TagResource/CreateTags/AddTags action

A resource is **untaggable** only if it has NEITHER indicator.

**Key findings from the latest scan:**
- 🔴 **534 specific resources** cannot be tagged
- ⚠️ Many services have mixed support (some resources taggable, others not)

## Quick Start

```bash
# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Run the primary detection tool
python detect_api_taggable.py
```

Output is saved to `output/` (latest) and `history/` (versioned).

---

## Scripts

| Script | Role | Description |
|--------|------|-------------|
| `detect_api_taggable.py` | **PRIMARY** | Authoritative resource-level detection |
| `detect_service_level.py` | SECONDARY | Quick service-level validation |
| `cfn_to_iam_mapper.py` | SUPPLEMENTARY | CloudFormation resource mapping |

## Output Files

- `output/api_taggable_resources.json`: Comprehensive untaggable resource list
- `output/service_level_untaggable.json`: Services without tagging API
- `history/`: Timestamped versions for change tracking

## Comparing Runs

```bash
python diff_runs.py  # Compare latest two runs
```

## Why This Matters

For SCP tagging policies, you need to **exclude untaggable resources** from tag enforcement:

1. **Service-level exclusions**: Entire services with no tagging API
2. **Resource-level exclusions**: Specific resources in mixed-support services

Without these exclusions, your SCP policies will block legitimate resource creation.

## Who Is This For?

- **Platform/Cloud Engineers** building SCP tagging policies
- **FinOps Teams** identifying cost allocation gaps from untaggable resources
- **Compliance Teams** understanding tagging enforcement limitations
- **Anyone** implementing AWS tagging strategies at scale

## Why aws:ResourceTag?

This tool checks for `aws:ResourceTag/${TagKey}` condition key presence, not just `CreateTags` or `TagResource` action support. Here's why:

- SCPs use `aws:ResourceTag` conditions to enforce tagging
- A resource could theoretically support `CreateTags` but lack `aws:ResourceTag` condition support
- Such resources would fail SCP evaluation even if tagged
- By checking for `aws:ResourceTag`, we identify what's compatible with SCP enforcement, not just what's taggable in general

## Out of Scope

This tool detects **untaggable resources**, not:

- **Usage metrics** (API requests, events processed): These are billing aggregations, not resources
- **Ephemeral items** (Lambda invocations, API calls): Transient actions without persistent state
- **Third party or Marketplace products**: Not in IAM Service Authorization Reference

## Known Limitations

- **Web scraping dependency**: Parses AWS HTML documentation. Structure changes could break detection. Integration tests help catch this early.
- **Point in time accuracy**: AWS adds and changes services regularly. Run quarterly or on demand for updates.

## Related

- Source: [IAM Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html)
