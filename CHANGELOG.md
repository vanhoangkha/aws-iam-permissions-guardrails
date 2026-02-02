# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Comprehensive best practices documentation (`COMPLETE_BEST_PRACTICES.md`) covering all 95 guardrails
- Quick reference guide (`QUICK_REFERENCE.md`) with deployment checklist
- Production-ready deployable SCPs in `deployable-policies/`:
  - `scp-critical-security.json` - Root user and security service protection
  - `scp-data-protection.json` - S3, KMS, RDS encryption controls
  - `scp-infrastructure-protection.json` - EC2, VPC, network controls
  - `scp-organization-protection.json` - Account and organization protection
- CloudFormation template (`cloudformation/deploy-all-scps.yaml`) for one-click deployment
- Automation scripts in `scripts/`:
  - `deploy_scps.py` - Automated SCP deployment to AWS Organizations
  - `analyze_policy.py` - IAM policy security analyzer
- Unit tests for SCP and CloudFormation validation
- GitHub Actions CI workflow for automated testing
