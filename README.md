# AWS Untaggable Resources Detector

## The Problem

**Tagging is critical for AWS cost allocation, compliance, and resource management.** But not all AWS resources support tagging - and AWS doesn't provide a single list of what can't be tagged.

This creates real problems:
- **SCP policies fail** when they enforce tags on untaggable resources
- **Cost allocation gaps** - untagged resources can't be attributed to teams/projects
- **Compliance blind spots** - you can't enforce what you can't tag
- **Manual maintenance hell** - keeping track of 1800+ untaggable resources across 460+ services

## The Solution

This tool automatically detects all AWS resources that cannot be tagged by parsing the authoritative source: the **IAM Service Authorization Reference**.

**Key findings from the latest scan:**
- 🔴 **156 AWS services** have no tagging support at all
- 🔴 **1800+ specific resources** cannot be tagged
- ⚠️ Many "taggable" services have mixed support (some resources taggable, others not)

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

- `output/api_taggable_resources.json` - Comprehensive untaggable resource list
- `output/service_level_untaggable.json` - Services without tagging API
- `history/` - Timestamped versions for change tracking

## Comparing Runs

```bash
python diff_runs.py  # Compare latest two runs
```

## Why This Matters

For SCP tagging policies, you need to **exclude untaggable resources** from tag enforcement:

1. **Service-level exclusions** - Entire services with no tagging API
2. **Resource-level exclusions** - Specific resources in mixed-support services

Without these exclusions, your SCP policies will block legitimate resource creation.

## Related

- [Spike ticket #595](https://github.com/ministryofjustice/cloud-optimisation-and-accountability/issues/595)
- Source: [IAM Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html)
