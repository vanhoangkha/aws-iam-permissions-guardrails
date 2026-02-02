#!/usr/bin/env python3
"""Validate CloudFormation templates."""
import unittest
import yaml
from pathlib import Path

# Custom loader for CloudFormation intrinsic functions
class CFNLoader(yaml.SafeLoader):
    pass

for tag in ['!Ref', '!Sub', '!GetAtt', '!Join', '!If', '!Equals', '!Not', '!And', '!Or']:
    CFNLoader.add_constructor(tag, lambda l, n: n.value)

class TestCloudFormation(unittest.TestCase):
    
    def test_valid_yaml(self):
        for f in Path(__file__).parent.parent.glob("cloudformation/*.yaml"):
            with open(f) as fp:
                yaml.load(fp, Loader=CFNLoader)
    
    def test_required_sections(self):
        cfn = Path(__file__).parent.parent / "cloudformation/deploy-all-scps.yaml"
        with open(cfn) as fp:
            template = yaml.load(fp, Loader=CFNLoader)
        self.assertIn("AWSTemplateFormatVersion", template)
        self.assertIn("Parameters", template)
        self.assertIn("Resources", template)

if __name__ == "__main__":
    unittest.main()
