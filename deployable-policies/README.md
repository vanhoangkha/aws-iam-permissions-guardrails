# Deployable SCP Policies

Ready-to-deploy Service Control Policies for AWS Organizations.

## Files

| File | Description | Priority |
|------|-------------|----------|
| `scp-critical-security.json` | Root user blocking, CloudTrail/GuardDuty/Config protection | Deploy First |
| `scp-data-protection.json` | S3 encryption, KMS protection, Glacier protection | High |
| `scp-infrastructure-protection.json` | IAM roles, CloudFormation, Lambda protection | High |
| `scp-organization-protection.json` | Org leave prevention, RAM, billing protection | Medium |

## Deployment

### Option 1: AWS CLI

```bash
# Deploy critical security SCP
aws organizations create-policy \
  --name "Critical-Security-Guardrails" \
  --type SERVICE_CONTROL_POLICY \
  --content file://scp-critical-security.json \
  --description "Blocks root user, protects CloudTrail/GuardDuty/Config"

# Attach to root (applies to all accounts)
aws organizations attach-policy \
  --policy-id p-xxxxxxxxxx \
  --target-id r-xxxx
```

### Option 2: CloudFormation

```bash
cd ../cloudformation
aws cloudformation deploy \
  --template-file deploy-all-scps.yaml \
  --stack-name security-guardrails \
  --parameter-overrides AutomationRoleName=YourAutomationRole
```

## Customization

Before deploying, replace these placeholders:

| Placeholder | Replace With |
|-------------|--------------|
| `INFRASTRUCTURE_AUTOMATION_ROLE` | Your automation role name (e.g., `OrganizationAccountAccessRole`) |
| `SECURITY_ADMIN_ROLE` | Your security admin role |
| `ENCRYPTION_ADMIN_ROLE` | Your KMS admin role |
| `BILLING_ADMIN_ROLE` | Your billing admin role |
| `IDENTITY_ADMIN_ROLE` | Your IAM admin role |
| `PROTECTED_ROLE_PREFIX` | Prefix for protected roles |
| `PROTECTED_STACK_PREFIX` | Prefix for protected CloudFormation stacks |
| `PROTECTED_FUNCTION_PREFIX` | Prefix for protected Lambda functions |
| `PROTECTED_TOPIC_PREFIX` | Prefix for protected SNS topics |
| `PROTECTED_LOG_GROUP_PREFIX` | Prefix for protected CloudWatch log groups |

## Policy Size Limits

AWS SCP size limit: **5,120 characters**

| Policy | Size | Status |
|--------|------|--------|
| scp-critical-security.json | ~2.5KB | OK |
| scp-data-protection.json | ~1.8KB | OK |
| scp-infrastructure-protection.json | ~2.8KB | OK |
| scp-organization-protection.json | ~1.6KB | OK |

## Testing

Before attaching to production OUs:

1. Create a test OU
2. Attach SCP to test OU
3. Move a test account to the OU
4. Verify expected denials work
5. Verify automation role exceptions work
