"""
Integration tests that hit real AWS documentation.

These tests verify:
1. AWS doc URLs are accessible
2. Expected HTML structure hasn't changed
3. We can parse real service pages correctly

Run with: pytest tests/test_integration.py -v
"""

import pytest
import requests

SERVICE_AUTH_REF_BASE = "https://docs.aws.amazon.com/service-authorization/latest/reference"
SERVICE_AUTH_REF_TOC = f"{SERVICE_AUTH_REF_BASE}/reference_policies_actions-resources-contextkeys.html"
CFN_SPEC_URL = "https://d1uauaxba7bl26.cloudfront.net/latest/gzip/CloudFormationResourceSpecification.json"


class TestAWSDocAccessibility:
    """Test that AWS documentation URLs are accessible."""
    
    def test_iam_service_auth_ref_toc_accessible(self):
        """Verify IAM Service Authorization Reference TOC is accessible."""
        response = requests.get(SERVICE_AUTH_REF_TOC, timeout=30)
        assert response.status_code == 200
        assert "Actions, resources, and condition keys" in response.text
    
    def test_cfn_spec_accessible(self):
        """Verify CloudFormation spec is accessible."""
        response = requests.get(CFN_SPEC_URL, timeout=30)
        assert response.status_code == 200
        data = response.json()
        assert "ResourceTypes" in data


class TestAWSDocStructure:
    """Test that AWS documentation structure matches expectations."""
    
    def test_service_list_contains_expected_count(self):
        """Verify we find a reasonable number of services."""
        from bs4 import BeautifulSoup
        
        response = requests.get(SERVICE_AUTH_REF_TOC, timeout=30)
        soup = BeautifulSoup(response.text, "lxml")
        
        services = []
        for link in soup.find_all("a", href=True):
            href = link.get("href", "")
            if "list_" in href and href.endswith(".html"):
                services.append(link.get_text(strip=True))
        
        assert len(services) >= 400, f"Expected 400+ services, found {len(services)}"
    
    def test_sample_service_page_has_expected_structure(self):
        """Verify a sample service page has expected tables."""
        from bs4 import BeautifulSoup
        
        ec2_url = f"{SERVICE_AUTH_REF_BASE}/list_amazonec2.html"
        response = requests.get(ec2_url, timeout=30)
        soup = BeautifulSoup(response.text, "lxml")
        
        tables = soup.find_all("table")
        assert len(tables) >= 2, "Expected at least 2 tables (actions, resources)"
        
        text = soup.get_text().lower()
        assert "actions defined by" in text
        assert "resource types defined by" in text
    
    def test_cfn_spec_has_expected_resource_count(self):
        """Verify CFN spec has a reasonable number of resource types."""
        response = requests.get(CFN_SPEC_URL, timeout=30)
        data = response.json()
        
        resource_types = data.get("ResourceTypes", {})
        assert len(resource_types) >= 1000, f"Expected 1000+ resources, found {len(resource_types)}"


class TestSampleServiceParsing:
    """Test parsing of known service pages."""
    
    def test_ec2_has_tagging_actions(self):
        """Verify EC2 page shows tagging support."""
        from bs4 import BeautifulSoup
        
        ec2_url = f"{SERVICE_AUTH_REF_BASE}/list_amazonec2.html"
        response = requests.get(ec2_url, timeout=30)
        soup = BeautifulSoup(response.text, "lxml")
        
        text = soup.get_text().lower()
        assert "createtags" in text or "tagresource" in text
    
    def test_artifact_has_no_tagging_actions(self):
        """Verify AWS Artifact (a known untaggable service) has no tagging actions."""
        from bs4 import BeautifulSoup
        
        artifact_url = f"{SERVICE_AUTH_REF_BASE}/list_awsartifact.html"
        response = requests.get(artifact_url, timeout=30)
        soup = BeautifulSoup(response.text, "lxml")
        
        text = soup.get_text().lower()
        assert "tagresource" not in text
        assert "createtags" not in text
