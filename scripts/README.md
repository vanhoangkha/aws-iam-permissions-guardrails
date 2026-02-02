# Scripts

Automation scripts for managing IAM permissions guardrails.

## deploy_scps.py

Deploy SCPs to AWS Organizations.

```bash
# Deploy all SCPs
python3 scripts/deploy_scps.py

# Deploy to specific OU
python3 scripts/deploy_scps.py -t ou-xxxx-xxxxxxxx

# Deploy single policy
python3 scripts/deploy_scps.py -p deployable-policies/scp-critical-security.json

# Dry run
python3 scripts/deploy_scps.py --dry-run
```

## analyze_policy.py

Analyze IAM policies for security issues.

```bash
# Analyze policy file
python3 scripts/analyze_policy.py -f policy.json

# Analyze IAM role
python3 scripts/analyze_policy.py -r MyRoleName
```

## Requirements

- Python 3.8+
- boto3
- AWS credentials configured
