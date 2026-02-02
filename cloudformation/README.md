# CloudFormation Templates

## deploy-all-scps.yaml

Deploys all 4 SCP policies to your AWS Organization.

### Prerequisites

- AWS Organizations enabled
- Management account access
- CloudFormation permissions

### Deploy

```bash
aws cloudformation deploy \
  --template-file deploy-all-scps.yaml \
  --stack-name security-guardrails \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    AutomationRoleName=OrganizationAccountAccessRole \
    SecurityAdminRoleName=SecurityAdmin \
    EncryptionAdminRoleName=KMSAdmin \
    BillingAdminRoleName=BillingAdmin \
    ProtectedRolePrefix=aws-controltower-
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| AutomationRoleName | OrganizationAccountAccessRole | Role exempt from most SCPs |
| SecurityAdminRoleName | SecurityAdminRole | Role for security administration |
| EncryptionAdminRoleName | EncryptionAdminRole | Role for KMS administration |
| BillingAdminRoleName | BillingAdminRole | Role for billing administration |
| ProtectedRolePrefix | aws-controltower- | Prefix for protected IAM roles |
| ProtectedLogGroupPrefix | aws-controltower/ | Prefix for protected log groups |

### Outputs

- `CriticalSecuritySCPId` - Policy ID for critical security SCP
- `DataProtectionSCPId` - Policy ID for data protection SCP
- `InfrastructureProtectionSCPId` - Policy ID for infrastructure SCP
- `OrganizationProtectionSCPId` - Policy ID for organization SCP

### Attach to OUs

After deployment, attach SCPs to target OUs:

```bash
# Get policy IDs from stack outputs
CRITICAL_SCP=$(aws cloudformation describe-stacks \
  --stack-name security-guardrails \
  --query 'Stacks[0].Outputs[?OutputKey==`CriticalSecuritySCPId`].OutputValue' \
  --output text)

# Attach to an OU
aws organizations attach-policy \
  --policy-id $CRITICAL_SCP \
  --target-id ou-xxxx-xxxxxxxx
```

### Delete

```bash
# First detach all policies from OUs
aws organizations detach-policy --policy-id p-xxx --target-id ou-xxx

# Then delete stack
aws cloudformation delete-stack --stack-name security-guardrails
```
