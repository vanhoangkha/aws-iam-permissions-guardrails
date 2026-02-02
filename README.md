# AWS IAM Permissions Guardrails

[![Validate SCPs](https://github.com/vanhoangkha/aws-iam-permissions-guardrails/actions/workflows/validate.yml/badge.svg)](https://github.com/vanhoangkha/aws-iam-permissions-guardrails/actions/workflows/validate.yml)
[![License](https://img.shields.io/badge/License-MIT--0-blue.svg)](LICENSE)

A comprehensive collection of **95 security guardrails** (26 SCPs + 69 IAM policies) for AWS Organizations, with ready-to-deploy templates and automation scripts.

## Features

- **95 Pre-built Guardrails** - Covering 20+ AWS services
- **Production-Ready SCPs** - Validated and under AWS size limits
- **One-Click Deployment** - CloudFormation and Python scripts
- **CI/CD Integration** - GitHub Actions workflow included
- **Comprehensive Documentation** - Best practices and quick reference

## Quick Start

### Option 1: CloudFormation

```bash
aws cloudformation deploy \
  --template-file cloudformation/deploy-all-scps.yaml \
  --stack-name iam-guardrails \
  --parameter-overrides \
    InfrastructureAutomationRole=MyTerraformRole \
    SecurityAdminRole=MySecurityRole
```

### Option 2: Python Script

```bash
# Deploy all SCPs to an OU
python3 scripts/deploy_scps.py -t ou-xxxx-xxxxxxxx

# Dry run first
python3 scripts/deploy_scps.py --dry-run
```

## Repository Structure

```
├── COMPLETE_BEST_PRACTICES.md    # Full documentation (95 guardrails)
├── QUICK_REFERENCE.md            # Deployment checklist
├── deployable-policies/          # Production-ready SCP JSON files
│   ├── scp-critical-security.json
│   ├── scp-data-protection.json
│   ├── scp-infrastructure-protection.json
│   └── scp-organization-protection.json
├── cloudformation/               # IaC templates
│   └── deploy-all-scps.yaml
├── scripts/                      # Automation tools
│   ├── deploy_scps.py
│   └── analyze_policy.py
├── guardrails/                   # Source guardrail definitions
└── tests/                        # Validation tests
```

## SCP Categories

| Category | Priority | Description |
|----------|----------|-------------|
| Critical Security | High | Root user restrictions, security service protection |
| Data Protection | High | S3, KMS, RDS encryption enforcement |
| Infrastructure | Medium | EC2, VPC, network controls |
| Organization | Medium | Account and organization protection |

## Documentation

- [Complete Best Practices](COMPLETE_BEST_PRACTICES.md) - All 95 guardrails documented
- [Quick Reference](QUICK_REFERENCE.md) - Deployment checklist and commands
- [Deployable Policies](deployable-policies/README.md) - SCP usage guide
- [CloudFormation Guide](cloudformation/README.md) - Template documentation
- [Scripts Guide](scripts/README.md) - Automation tools

## Requirements

- AWS Organizations with SCPs enabled
- Python 3.8+ (for scripts)
- AWS CLI configured with appropriate permissions

## Testing

```bash
python3 -m unittest discover tests/ -v
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [CONTRIBUTING.md](CONTRIBUTING.md#security-issue-notifications) for reporting security issues.

## License

This project is licensed under the MIT-0 License. See [LICENSE](LICENSE).
