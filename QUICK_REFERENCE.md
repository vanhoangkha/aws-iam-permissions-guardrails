# Quick Reference: AWS IAM Permissions Guardrails

## SCP Deployment Checklist

- [ ] Review SCPs in `deployable-policies/`
- [ ] Replace placeholder roles (INFRASTRUCTURE_AUTOMATION_ROLE, etc.)
- [ ] Test in sandbox OU first
- [ ] Deploy to production OUs gradually
- [ ] Monitor CloudTrail for denied actions

## Critical SCPs (Deploy First)

| SCP | Purpose |
|-----|---------|
| scp-critical-security | Root user, security services protection |
| scp-data-protection | S3, KMS, RDS encryption |

## Role Placeholders

Replace these in SCPs before deployment:

| Placeholder | Purpose |
|-------------|---------|
| `INFRASTRUCTURE_AUTOMATION_ROLE` | CI/CD, Terraform |
| `SECURITY_ADMIN_ROLE` | Security team |
| `ENCRYPTION_ADMIN_ROLE` | KMS management |
| `BILLING_ADMIN_ROLE` | Cost management |
| `IDENTITY_ADMIN_ROLE` | IAM administration |

## Common Commands

```bash
# Deploy all SCPs
python3 scripts/deploy_scps.py -t ou-xxxx-xxxxxxxx

# Validate SCPs
python3 -m unittest discover tests/

# Analyze role permissions
python3 scripts/analyze_policy.py -r RoleName
```

## AWS Documentation

- [SCP Best Practices](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_best_practices.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
