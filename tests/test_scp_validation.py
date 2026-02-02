#!/usr/bin/env python3
"""Validate SCP JSON files for AWS compliance."""
import json
import os
import unittest
from pathlib import Path

MAX_SCP_SIZE = 5120  # AWS limit

class TestSCPValidation(unittest.TestCase):
    
    def get_scp_files(self):
        root = Path(__file__).parent.parent
        return list(root.glob("deployable-policies/*.json")) + list(root.glob("guardrails/**/SCP-*.json"))
    
    def test_valid_json(self):
        for f in self.get_scp_files():
            with open(f) as fp:
                json.load(fp)  # Raises if invalid
    
    def test_size_limit(self):
        for f in self.get_scp_files():
            size = os.path.getsize(f)
            self.assertLessEqual(size, MAX_SCP_SIZE, f"{f.name} exceeds {MAX_SCP_SIZE} bytes")
    
    def test_required_fields(self):
        for f in Path(__file__).parent.parent.glob("deployable-policies/*.json"):
            with open(f) as fp:
                policy = json.load(fp)
            self.assertIn("Version", policy)
            self.assertIn("Statement", policy)

if __name__ == "__main__":
    unittest.main()
