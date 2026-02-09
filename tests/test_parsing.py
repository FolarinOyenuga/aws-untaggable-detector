"""Tests for HTML parsing functions."""

import pytest
from bs4 import BeautifulSoup

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from detect_api_taggable import extract_resource_types, extract_tagging_actions_and_resources


SAMPLE_RESOURCE_TYPES_HTML = """
<html>
<body>
<h2>Resource types defined by Amazon EC2</h2>
<table>
    <tr>
        <th>Resource types</th>
        <th>ARN</th>
        <th>Condition keys</th>
    </tr>
    <tr>
        <td>instance</td>
        <td>arn:aws:ec2:region:account:instance/instance-id</td>
        <td></td>
    </tr>
    <tr>
        <td>volume</td>
        <td>arn:aws:ec2:region:account:volume/volume-id</td>
        <td></td>
    </tr>
    <tr>
        <td>snapshot*</td>
        <td>arn:aws:ec2:region:account:snapshot/snapshot-id</td>
        <td></td>
    </tr>
</table>
</body>
</html>
"""

SAMPLE_ACTIONS_HTML = """
<html>
<body>
<h2>Actions defined by Amazon EC2</h2>
<table>
    <tr>
        <th>Actions</th>
        <th>Description</th>
        <th>Resource types</th>
    </tr>
    <tr>
        <td><a>CreateTags</a></td>
        <td>Grants permission to create tags</td>
        <td><a>instance</a>, <a>volume</a></td>
    </tr>
    <tr>
        <td><a>DeleteTags</a></td>
        <td>Grants permission to delete tags</td>
        <td><a>instance</a>, <a>volume</a></td>
    </tr>
    <tr>
        <td><a>RunInstances</a></td>
        <td>Grants permission to run instances</td>
        <td><a>instance</a></td>
    </tr>
</table>
</body>
</html>
"""

SAMPLE_NO_TAGGING_HTML = """
<html>
<body>
<h2>Actions defined by AWS Artifact</h2>
<table>
    <tr>
        <th>Actions</th>
        <th>Description</th>
        <th>Resource types</th>
    </tr>
    <tr>
        <td><a>GetReport</a></td>
        <td>Grants permission to get a report</td>
        <td><a>report</a></td>
    </tr>
</table>
</body>
</html>
"""


class TestExtractResourceTypes:
    def test_extracts_resource_names(self):
        soup = BeautifulSoup(SAMPLE_RESOURCE_TYPES_HTML, "lxml")
        resources = extract_resource_types(soup)
        
        assert "instance" in resources
        assert "volume" in resources
        assert "snapshot" in resources
    
    def test_returns_empty_list_when_no_table(self):
        soup = BeautifulSoup("<html><body><h2>No table here</h2></body></html>", "lxml")
        resources = extract_resource_types(soup)
        
        assert resources == []
    
    def test_returns_empty_list_when_no_resource_section(self):
        soup = BeautifulSoup("<html><body><h2>Actions</h2><table></table></body></html>", "lxml")
        resources = extract_resource_types(soup)
        
        assert resources == []


class TestExtractTaggingActionsAndResources:
    def test_extracts_tagging_actions(self):
        soup = BeautifulSoup(SAMPLE_ACTIONS_HTML, "lxml")
        result = extract_tagging_actions_and_resources(soup)
        
        assert "createtags" in result["tagging_actions"]
    
    def test_extracts_taggable_resources(self):
        soup = BeautifulSoup(SAMPLE_ACTIONS_HTML, "lxml")
        result = extract_tagging_actions_and_resources(soup)
        
        assert "instance" in result["taggable_resources"]
        assert "volume" in result["taggable_resources"]
    
    def test_returns_empty_when_no_tagging_actions(self):
        soup = BeautifulSoup(SAMPLE_NO_TAGGING_HTML, "lxml")
        result = extract_tagging_actions_and_resources(soup)
        
        assert result["tagging_actions"] == []
        assert result["taggable_resources"] == []
    
    def test_returns_empty_when_no_actions_section(self):
        soup = BeautifulSoup("<html><body><h2>Resource types</h2></body></html>", "lxml")
        result = extract_tagging_actions_and_resources(soup)
        
        assert result["tagging_actions"] == []
        assert result["taggable_resources"] == []
