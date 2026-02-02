#!/usr/bin/env python3
"""Deploy SCPs to AWS Organizations."""
import argparse
import json
import boto3
from pathlib import Path

def deploy_scp(org_client, name: str, policy_path: Path, target_ids: list = None):
    """Create or update an SCP."""
    with open(policy_path) as f:
        content = f.read()
    
    # Check if policy exists
    existing = None
    for page in org_client.get_paginator('list_policies').paginate(Filter='SERVICE_CONTROL_POLICY'):
        for policy in page['Policies']:
            if policy['Name'] == name:
                existing = policy['Id']
                break
    
    if existing:
        org_client.update_policy(PolicyId=existing, Content=content)
        print(f"Updated: {name}")
        policy_id = existing
    else:
        resp = org_client.create_policy(
            Content=content, Description=f"SCP: {name}", Name=name, Type='SERVICE_CONTROL_POLICY'
        )
        policy_id = resp['Policy']['PolicySummary']['Id']
        print(f"Created: {name}")
    
    # Attach to targets
    for target_id in (target_ids or []):
        try:
            org_client.attach_policy(PolicyId=policy_id, TargetId=target_id)
            print(f"  Attached to: {target_id}")
        except org_client.exceptions.DuplicatePolicyAttachmentException:
            print(f"  Already attached to: {target_id}")

def main():
    parser = argparse.ArgumentParser(description='Deploy SCPs to AWS Organizations')
    parser.add_argument('--target', '-t', action='append', help='Target OU/Account IDs')
    parser.add_argument('--policy', '-p', help='Specific policy file (default: all)')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be deployed')
    args = parser.parse_args()
    
    policies_dir = Path(__file__).parent.parent / 'deployable-policies'
    files = [Path(args.policy)] if args.policy else list(policies_dir.glob('*.json'))
    
    if args.dry_run:
        for f in files:
            print(f"Would deploy: {f.stem}")
        return
    
    org = boto3.client('organizations')
    for f in files:
        if f.suffix == '.json' and not f.name.startswith('README'):
            deploy_scp(org, f.stem, f, args.target)

if __name__ == '__main__':
    main()
