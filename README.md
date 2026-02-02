# AWS IAM Permissions Guardrails

A collection of **97 security guardrails** for AWS environments using Service Control Policies (SCPs) and IAM permission boundaries.

## Quick Start

```bash
# Deploy critical SCPs to your AWS Organization
cd deployable-policies
aws organizations create-policy --name "Critical-Security-Guardrails" \
  --type SERVICE_CONTROL_POLICY \
  --content file://scp-critical-security.json
```

## Repository Structure

```
├── COMPLETE_BEST_PRACTICES.md    # Full documentation of all 97 guardrails
├── deployable-policies/          # Ready-to-deploy SCP JSON files
│   ├── scp-critical-security.json
│   ├── scp-data-protection.json
│   ├── scp-infrastructure-protection.json
│   └── scp-organization-protection.json
├── cloudformation/               # CloudFormation templates
│   └── deploy-all-scps.yaml
├── guardrails/                   # Source guardrail definitions by service
└── access-analyzer/              # IAM Access Analyzer automation
```

## Guardrail Categories

| Category | Count | Priority |
|----------|-------|----------|
| Root User & IAM Protection | 5 SCPs | Critical |
| Security Services (CloudTrail, GuardDuty, Config) | 5 SCPs | Critical |
| Data Protection (S3, KMS, Glacier) | 7 SCPs | High |
| Infrastructure Protection | 5 SCPs | High |
| Organization & Account | 4 SCPs | Medium |
| IAM Permission Boundaries | 11 policies | Variable |
| Service-Specific Controls | 60+ checks | Variable |

## Critical SCPs (Deploy First)

| ID | Control | Actions Blocked |
|----|---------|-----------------|
| SCP-IAM-1 | Block root user | All actions |
| SCP-CLOUDTRAIL-1 | Protect CloudTrail | Delete, Stop, Update |
| SCP-GUARDDUTY-1 | Protect GuardDuty | Delete, Disable |
| SCP-CONFIG-1 | Protect AWS Config | Delete, Stop |
| SCP-S3-1 | Protect S3 public access block | PutAccountPublicAccessBlock |
| SCP-S3-2 | Require S3 encryption | Unencrypted PutObject |
| SCP-KMS-1 | Protect KMS keys | ScheduleKeyDeletion |

## Documentation

- **[COMPLETE_BEST_PRACTICES.md](COMPLETE_BEST_PRACTICES.md)** - Full reference of all 97 guardrails
- **[deployable-policies/](deployable-policies/)** - Ready-to-deploy JSON policies
- **[cloudformation/](cloudformation/)** - Infrastructure as Code templates

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
