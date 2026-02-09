# Spike Findings: AWS Untaggable Resources Detection

## Overview

Automated detection of AWS resources that cannot be tagged, for SCP policy management.

## Approach

Two-level detection based on IAM Service Authorization Reference:

### Service-Level (`detect_service_level.py`)
- Identifies services with NO tagging API actions (TagResource/UntagResource)
- All resources in these services are untaggable
- **Result**: 156 services, 646 resources

### Resource-Level
- Specific resources that can't be tagged within otherwise taggable services
- Requires manual verification or known verified list
- **Result**: See ticket #560 verified list (77 resources)

## Key Finding

For SCP policies, use **hybrid approach**:
1. **Service-level exclusions** for services with no tagging API
2. **Resource-level exclusions** for specific resources in taggable services

## Quarterly Automation

To automate reviews:
1. Run `detect_service_level.py` quarterly
2. Compare results against previous run
3. Flag changes (newly taggable = remove from SCP exceptions)
4. Update SCP policies accordingly

## References

- [IAM Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html)
- Related tickets: #560, #564
