#!/usr/bin/env python3
"""Analyze IAM policies for security issues."""
import argparse
import json
import boto3
from pathlib import Path

DANGEROUS_ACTIONS = ['*', 'iam:*', 's3:*', 'ec2:*', 'sts:AssumeRole']
DANGEROUS_RESOURCES = ['*']

def analyze_policy(policy: dict) -> list:
    """Return list of findings."""
    findings = []
    for stmt in policy.get('Statement', []):
        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        
        if stmt.get('Effect') == 'Allow':
            for action in actions:
                if action in DANGEROUS_ACTIONS or action.endswith(':*'):
                    findings.append(f"Overly permissive action: {action}")
            if '*' in resources and any(a in DANGEROUS_ACTIONS for a in actions):
                findings.append("Wildcard resource with dangerous actions")
    return findings

def main():
    parser = argparse.ArgumentParser(description='Analyze IAM policies')
    parser.add_argument('--file', '-f', help='Policy JSON file')
    parser.add_argument('--role', '-r', help='IAM role name to analyze')
    args = parser.parse_args()
    
    if args.file:
        with open(args.file) as f:
            policy = json.load(f)
        findings = analyze_policy(policy)
    elif args.role:
        iam = boto3.client('iam')
        findings = []
        # Inline policies
        for name in iam.list_role_policies(RoleName=args.role)['PolicyNames']:
            doc = iam.get_role_policy(RoleName=args.role, PolicyName=name)['PolicyDocument']
            findings.extend([f"[{name}] {f}" for f in analyze_policy(doc)])
        # Attached policies
        for p in iam.list_attached_role_policies(RoleName=args.role)['AttachedPolicies']:
            ver = iam.get_policy(PolicyArn=p['PolicyArn'])['Policy']['DefaultVersionId']
            doc = iam.get_policy_version(PolicyArn=p['PolicyArn'], VersionId=ver)['PolicyVersion']['Document']
            findings.extend([f"[{p['PolicyName']}] {f}" for f in analyze_policy(doc)])
    else:
        parser.print_help()
        return
    
    if findings:
        print("Security findings:")
        for f in findings:
            print(f"  - {f}")
    else:
        print("No issues found")

if __name__ == '__main__':
    main()
