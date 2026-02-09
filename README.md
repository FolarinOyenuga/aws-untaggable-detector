# AWS Untaggable Resources Detector

Automated detection of untaggable AWS resources for SCP policy management (#564)

## Overview

Detects AWS resources that cannot be tagged at two levels:
- **Service-level**: Services with NO tagging API (all resources untaggable)
- **Resource-level**: Specific resources that can't be tagged in otherwise taggable services

## Why Two Levels?

For SCP policies, you need both:
1. **Service-level exclusions** - Entire services that don't support tagging
2. **Resource-level exclusions** - Specific resources in services that DO support tagging

## Project Structure

```
aws-untaggable-detector/
├── detect_service_level.py      # Identifies services with no tagging API
├── detect_resource_level.py     # Identifies resources in taggable services
├── resource_groups_api/         # Supplementary RGTAPI validation
├── output/                      # Generated reports
├── docs/                        # Documentation
└── requirements.txt
```

## Usage

```bash
# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run service-level detection first
python detect_service_level.py

# Then run resource-level detection
python detect_resource_level.py
```

## Output

- `output/service_level_untaggable.json` - Services with no tagging API
- `output/resource_level_analysis.json` - Resource-level analysis

## Related

- Spike ticket: #564
- Related to: #560 (Confirm which AWS Resources can't be tagged)
- Source: [IAM Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html)
