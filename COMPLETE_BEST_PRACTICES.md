# AWS IAM Permissions Guardrails - Complete Best Practices Reference

> Compiled from repository guardrails + AWS Official Documentation

## AWS Official IAM Security Best Practices

*Source: [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)*

| # | Best Practice | Description |
|---|---------------|-------------|
| 1 | **Use federation with IdP** | Require human users to use temporary credentials via identity provider |
| 2 | **Use IAM roles for workloads** | Require workloads to use temporary credentials with IAM roles |
| 3 | **Require MFA** | Enable multi-factor authentication for all users |
| 4 | **Rotate access keys** | Update access keys when needed for long-term credential use cases |
| 5 | **Protect root user** | Safeguard root credentials, avoid daily use |
| 6 | **Apply least-privilege** | Grant only permissions required to perform a task |
| 7 | **Start with AWS managed policies** | Use managed policies, then refine to least-privilege |
| 8 | **Use IAM Access Analyzer** | Generate least-privilege policies based on access activity |
| 9 | **Review unused access** | Regularly remove unused users, roles, permissions, credentials |
| 10 | **Use policy conditions** | Restrict access with conditions (e.g., require TLS, source IP) |
| 11 | **Verify public/cross-account access** | Use IAM Access Analyzer to review external access |
| 12 | **Validate IAM policies** | Use IAM Access Analyzer for 100+ policy checks |
| 13 | **Use SCPs for guardrails** | Establish permissions guardrails across multiple accounts |
| 14 | **Use RCPs for resource controls** | Use Resource Control Policies for resource-level guardrails |
| 15 | **Use permissions boundaries** | Delegate permissions management within an account |

## AWS Control Tower Mandatory Controls

*Source: [AWS Control Tower Controls Reference](https://docs.aws.amazon.com/controltower/latest/controlreference/mandatory-controls.html)*

| Control | Description |
|---------|-------------|
| Disallow changes to CloudTrail | Protect CloudTrail configuration |
| Disallow changes to AWS Config | Protect Config recorder and rules |
| Disallow changes to IAM roles created by Control Tower | Protect automation roles |
| Disallow changes to Lambda functions | Protect Control Tower Lambda functions |
| Disallow changes to SNS topics | Protect notification topics |
| Disallow changes to S3 buckets in Log Archive | Protect logging buckets |
| Disallow deletion of Log Archive | Prevent log bucket deletion |

---

## Table of Contents
1. [Service Control Policies (SCPs)](#service-control-policies-scps)
2. [IAM Permission Boundaries](#iam-permission-boundaries)
3. [Service-Specific Controls](#service-specific-controls)

---

## Service Control Policies (SCPs)

### Critical - Root User & IAM Protection

| ID | Control | Actions | Condition |
|----|---------|---------|-----------|
| **SCP-IAM-1** | Block all root user actions | `*` | `ArnLike: aws:PrincipalArn: arn:aws:iam::*:root` |
| **SCP-IAM-2** | Prevent root access key creation | `iam:CreateAccessKey` | Resource: `arn:aws:iam::*:root` |
| **SCP-IAM-3** | Protect specific IAM roles | `iam:AttachRolePolicy`, `iam:DeleteRole`, `iam:PutRolePolicy`, `iam:UpdateRole`, etc. | `ArnNotLike` exception for automation role |
| **SCP-IAM-4** | Prevent UpdateAssumeRolePolicy on protected roles | `iam:UpdateAssumeRolePolicy` | `ArnNotLike` exception |
| **SCP-IAM-5** | Prevent specific IAM actions | `iam:AttachUserPolicy`, `iam:CreateAccessKey`, `iam:CreateUser`, `iam:PutUserPolicy`, `iam:DeleteSAMLProvider` | `ArnNotLike` exception |

### Critical - Security Services Protection

| ID | Control | Actions Denied |
|----|---------|----------------|
| **SCP-CLOUDTRAIL-1** | Protect CloudTrail | `cloudtrail:DeleteTrail`, `cloudtrail:StopLogging`, `cloudtrail:UpdateTrail`, `cloudtrail:PutEventSelectors` |
| **SCP-GUARDDUTY-1** | Protect GuardDuty | `guardduty:DeleteDetector`, `guardduty:StopMonitoringMembers`, `guardduty:UpdateDetector`, `guardduty:Disassociate*`, `guardduty:DeleteIPSet`, `guardduty:DeleteThreatIntelSet` |
| **SCP-CONFIG-1** | Protect AWS Config | `config:DeleteConfigurationRecorder`, `config:StopConfigurationRecorder`, `config:DeleteDeliveryChannel`, `config:DeleteRetentionConfiguration`, `config:PutConfigurationRecorder` |
| **SCP-CONFIG-2** | Protect tagged Config rules | `config:DeleteConfigRule`, `config:PutConfigRule`, `config:TagResource`, `config:UntagResource` (with tag condition) |
| **SCP-CLOUDWATCH-1** | Protect CloudWatch Logs | `logs:DeleteLogGroup`, `logs:DeleteLogStream` |

### High - Data Protection

| ID | Control | Actions | Condition |
|----|---------|---------|-----------|
| **SCP-S3-1** | Prevent disabling S3 public access block | `s3:PutAccountPublicAccessBlock` | `ArnNotLike` exception |
| **SCP-S3-2** | Require S3 encryption | `s3:PutObject` | `Null: s3:x-amz-server-side-encryption: true` |
| **SCP-S3-3** | Prevent public S3 objects | `s3:PutObjectAcl`, `s3:PutObjectVersionAcl` | `StringNotEquals: s3:x-amz-acl: private` |
| **SCP-S3-4** | Protect specific S3 buckets from deletion | `s3:DeleteBucket`, `s3:DeleteObject`, `s3:DeleteObjectVersion`, etc. | Resource-based |
| **SCP-S3-5** | Prevent access to specific S3 buckets | All Get/List S3 actions | `ArnNotLike` exception for security roles |
| **SCP-KMS-1** | Prevent KMS key deletion | `kms:ScheduleKeyDeletion` | `ArnNotLike` exception |
| **SCP-GLACIER-1** | Prevent Glacier deletion | `glacier:DeleteArchive`, `glacier:DeleteVault` | None (absolute deny) |

### High - Infrastructure Protection

| ID | Control | Actions |
|----|---------|---------|
| **SCP-CLOUDFORMATION-1** | Protect CloudFormation stacks | `cloudformation:DeleteStack`, `cloudformation:UpdateStack`, `cloudformation:ExecuteChangeSet`, `cloudformation:CreateChangeSet`, etc. |
| **SCP-LAMBDA-1** | Protect Lambda functions | `lambda:DeleteFunction`, `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration`, `lambda:AddPermission`, `lambda:RemovePermission` |
| **SCP-EC2-1** | Prevent disabling EBS encryption | `ec2:DisableEbsEncryptionByDefault` |
| **SCP-EC2-2** | Prevent default VPC creation | `ec2:CreateDefaultVpc`, `ec2:CreateDefaultSubnet` |
| **SCP-SNS-1** | Protect SNS topics | `sns:DeleteTopic`, `sns:AddPermission`, `sns:RemovePermission`, `sns:SetTopicAttributes` |

### Medium - Organization & Account Protection

| ID | Control | Actions |
|----|---------|---------|
| **SCP-ORGANIZATIONS-1** | Prevent leaving organization | `organizations:LeaveOrganization`, `organizations:DeleteOrganization` |
| **SCP-RAM-1** | Prevent external resource sharing | All actions when `ram:AllowsExternalPrincipals: true` |
| **SCP-ACCOUNT-1** | Prevent region changes | `account:EnableRegion`, `account:DisableRegion` |
| **SCP-BILLING-1** | Protect billing settings | `aws-portal:ModifyAccount`, `aws-portal:ModifyBilling`, `aws-portal:ModifyPaymentMethods` |

---

## IAM Permission Boundaries

### IAM Management Controls

| ID | Guardrail | Sensitive Actions | Remediation |
|----|-----------|-------------------|-------------|
| **IAM-IAM-1** | IAM User/MFA management for authorized principals only | `iam:CreateUser`, `iam:DeleteUser`, `iam:CreateAccessKey`, `iam:EnableMFADevice`, `iam:DeactivateMFADevice`, `iam:AddUserToGroup`, etc. | Restrict to Security Operations |
| **IAM-IAM-2** | Role/Policy management for build automation only | `iam:CreateRole`, `iam:DeleteRole`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`, `iam:CreateSAMLProvider` | Restrict to automation roles |
| **IAM-IAM-3** | Caution with IP restrictions | N/A | Use `aws:SourceIp` on `AssumeRole*` instead of all actions |
| **IAM-IAM-4** | Protect Permission Boundary policies | `iam:CreatePolicyVersion`, `iam:DeletePolicy`, `iam:DeletePolicyVersion`, `iam:SetDefaultPolicyVersion` | Deny on boundary policy ARNs |
| **IAM-IAM-5** | Require boundaries on delegated admin roles | `iam:CreateRole` | Condition: `iam:PermissionsBoundary` must be set |
| **IAM-IAM-6** | Scope iam:PassRole appropriately | `iam:PassRole` | Specify Resources and `iam:PassedToService` condition |
| **IAM-IAM-7** | Restrict account enumeration | `iam:GetAccountAuthorizationDetails` | Whitelist only |
| **IAM-IAM-8** | Restrict user creation | `iam:CreateUser` | Remove unless whitelisted |
| **IAM-IAM-9** | Deny high-risk reconnaissance APIs | `s3:ListAllMyBuckets`, `kms:ListKeys`, `iam:Get*`, `iam:List*`, `organizations:Describe*`, `ec2:TerminateInstances` | Add deny policy to service roles |
| **IAM-IAM-10** | Scope PassRole with trust policy | `iam:PassRole` | Specify target AWS service in trust policy |
| **IAM-IAM-11** | Full IAM management restriction | All 70+ IAM modification actions | Deny to non-whitelisted principals |

---

## Service-Specific Controls

### KMS (Key Management Service)

| ID | Guardrail | Action | Best Practice |
|----|-----------|--------|---------------|
| **IAM-KMS-1** | Include root in key policy | N/A | Prevents key lockout |
| **IAM-KMS-2** | Restrict DeleteImportedKeyMaterial | `kms:DeleteImportedKeyMaterial` | Authorized principals only |
| **IAM-KMS-3** | Restrict CMK deletion | `kms:ScheduleKeyDeletion` | Authorized principals only |
| **IAM-KMS-4** | Restrict CMK disabling | `kms:DisableKey` | Authorized principals only |
| **IAM-KMS-5** | Restrict PutKeyPolicy | `kms:PutKeyPolicy` | Authorized principals only |
| **IAM-KMS-6** | Use kms:ViaService condition | N/A | Scope to specific AWS services |
| **IAM-KMS-7** | Restrict DisableKeyRotation | `kms:DisableKeyRotation` | Authorized principals only |
| **IAM-KMS-8** | Separation of duties | N/A | Separate key admin from crypto usage |
| **IAM-KMS-9** | Restrict all KMS admin actions | 21 admin actions | Authorized principals only |

### S3 (Simple Storage Service)

| ID | Guardrail | Best Practice |
|----|-----------|---------------|
| **IAM-S3-1** | Scope VPC Endpoint Policy | Use `aws:PrincipalOrgID` condition |
| **IAM-S3-2** | Restrict GetObject for sensitive data | Scope to authorized principals, use CMK encryption |
| **IAM-S3-3** | Enforce storage class | Use `s3:x-amz-storage-class` condition |
| **IAM-S3-4** | Restrict S3 management | 47 management actions for authorized principals only |

### S3 Access Points

| ID | Guardrail | Best Practice |
|----|-----------|---------------|
| **IAM-S3-AP-1** | Validate VPC for access points | Check VPC exists before creation |
| **IAM-S3-AP-2** | Block public access | Set `PublicAccessBlockConfiguration` |
| **IAM-S3-AP-3** | Restrict to account-owned access points | Use `s3:DataAccessPointAccount` condition |
| **IAM-S3-AP-4** | Limit bucket access to access points | Use `s3:DataAccessPointAccount` in bucket policy |
| **IAM-S3-AP-5** | Require VPC origin | Use `s3:AccessPointNetworkOrigin: VPC` condition |
| **IAM-S3-AP-6** | Tag-based object access | Use `s3:ExistingObjectTag` condition |

### Lambda

| ID | Guardrail | Best Practice |
|----|-----------|---------------|
| **IAM-LAMBDA-1** | Scope API Gateway invocations | Use `aws:SourceArn` condition |
| **IAM-LAMBDA-2** | Restrict Lambda management | 29 management actions for authorized principals only |

### RDS

| ID | Guardrail | Best Practice |
|----|-----------|---------------|
| **IAM-RDS-1** | Separation of duties for KMS | Separate DB admin from KMS key access |
| **IAM-RDS-2** | Require encryption | Use `rds:StorageEncrypted` condition |
| **IAM-RDS-3** | Restrict snapshot restore | Scope `RestoreDBInstanceFromS3` to authorized principals |

### Secrets Manager

| ID | Guardrail | Best Practice |
|----|-----------|---------------|
| **IAM-SECRETSMANAGER-1** | Restrict DeleteSecret | Use `secretsmanager:SecretId` and tag conditions |
| **IAM-SECRETSMANAGER-2** | Restrict GetSecretValue | Scope to authorized principals with conditions |
| **IAM-SECRETSMANAGER-3** | Separation of duties | Separate CreateSecret from Get/PutSecretValue |

### STS (Security Token Service)

| ID | Guardrail | Best Practice |
|----|-----------|---------------|
| **IAM-STS-1** | Use external ID for third parties | Add `sts:ExternalId` condition |
| **IAM-STS-2** | Avoid Principal "*" without conditions | Use `aws:PrincipalOrgId` or `aws:PrincipalArn` |
| **IAM-STS-3** | Validate cross-account principals | Whitelist approved accounts |
| **IAM-STS-4** | Control console vs programmatic access | Use `saml:aud` attribute |
| **IAM-STS-5** | IP restrictions on AssumeRole | Use `aws:SourceIp` in trust policy |
| **IAM-STS-6** | Restrict sts:TagSession | Remove if using tag-based access control |

### SSM (Systems Manager)

| ID | Guardrail | Best Practice |
|----|-----------|---------------|
| **IAM-SSM-1** | Scope SendCommand | Use resource ARNs or `ssm:ResourceTag` condition |
| **IAM-SSM-2** | Scope StartSession | Use `ssm:ResourceTag` condition |

### SQS

| ID | Guardrail | Best Practice |
|----|-----------|---------------|
| **IAM-SQS-1** | Use sourceArn for service calls | Add `aws:SourceArn` condition |
| **IAM-SQS-2** | Restrict SendMessage | Scope to authorized principals |
| **IAM-SQS-3** | Restrict ReceiveMessage | Scope to authorized principals |

### EC2 Controls

| ID | Guardrail | Best Practice |
|----|-----------|---------------|
| **IAM-EC2-1** | Restrict EC2 termination | Scope `ec2:TerminateInstances` to authorized principals |
| **IAM-EC2-2** | Restrict AMI usage | Use `ec2:ImageId` condition for approved AMIs |
| **IAM-EC2-3** | Restrict network modifications | Scope VPC/subnet/route table actions to network admins |
| **IAM-EC2-4** | Scope sensitive EC2 actions | Restrict `RunInstances`, `StopInstances`, `StartInstances` |
| **IAM-EC2-5** | Restrict security group management | Scope `AuthorizeSecurityGroup*`, `RevokeSecurityGroup*` |
| **IAM-EC2-6** | Full EC2 management restriction | 50+ EC2 actions for authorized principals only |

### CloudTrail Controls

| ID | Guardrail | Best Practice |
|----|-----------|---------------|
| **IAM-CLOUDTRAIL-1** | Prevent DeleteTrail/StopLogging | Deny or restrict to security admins |
| **IAM-CLOUDTRAIL-2** | Restrict UpdateTrail | Authorized principals only |
| **IAM-CLOUDTRAIL-3** | Protect CloudTrail S3 bucket | Use `aws:PrincipalOrgID` or `aws:SourceAccount` |
| **IAM-CLOUDTRAIL-4** | Restrict PutEventSelectors | Authorized principals only |
| **IAM-CLOUDTRAIL-5** | Full CloudTrail admin restriction | All admin actions for authorized principals |

### Other Services

| ID | Service | Guardrail |
|----|---------|-----------|
| **IAM-EKS-1** | EKS | Restrict cluster management to authorized principals |
| **IAM-ECR-1** | ECR | Restrict repository creation/deletion |
| **IAM-ECR-2** | ECR | Restrict image push/pull to authorized principals |
| **IAM-CODECOMMIT-1** | CodeCommit | Restrict repository management |
| **IAM-GUARDDUTY-1** | GuardDuty | Restrict detector management |
| **IAM-ELASTICSEARCH-1** | OpenSearch | Restrict domain management |
| **IAM-SES-1** | SES | Use `aws:Referer` for S3 integration |
| **IAM-BILLING-1** | Billing | Restrict billing access |
| **IAM-BUDGETS-1** | Budgets | Restrict budget management |

---

## Quick Implementation Checklist

### Mandatory (Deploy Immediately)
- [ ] SCP-IAM-1: Block root user
- [ ] SCP-IAM-2: Block root access keys
- [ ] SCP-CLOUDTRAIL-1: Protect CloudTrail
- [ ] SCP-GUARDDUTY-1: Protect GuardDuty
- [ ] SCP-CONFIG-1: Protect AWS Config
- [ ] SCP-S3-1: Protect S3 public access block
- [ ] SCP-S3-2: Require S3 encryption
- [ ] SCP-KMS-1: Protect KMS keys
- [ ] SCP-ORGANIZATIONS-1: Prevent org leave
- [ ] SCP-RAM-1: Block external sharing

### Recommended (High Priority)
- [ ] SCP-IAM-3: Protect IAM roles
- [ ] SCP-EC2-1: Require EBS encryption
- [ ] SCP-S3-3: Prevent public objects
- [ ] SCP-CLOUDWATCH-1: Protect logs
- [ ] IAM-IAM-4: Protect permission boundaries
- [ ] IAM-IAM-6: Scope PassRole

### Elective (Based on Requirements)
- [ ] SCP-LAMBDA-1: Protect Lambda functions
- [ ] SCP-SNS-1: Protect SNS topics
- [ ] SCP-S3-4/5: Protect specific buckets
- [ ] SCP-CLOUDFORMATION-1: Protect stacks

---

## Example SCP Template

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootUser",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "ArnLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    },
    {
      "Sid": "ProtectSecurityServices",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "guardduty:DeleteDetector",
        "config:DeleteConfigurationRecorder",
        "config:StopConfigurationRecorder"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalARN": "arn:aws:iam::*:role/InfraAutomationRole"
        }
      }
    },
    {
      "Sid": "RequireS3Encryption",
      "Effect": "Deny",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::*/*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption": "true"
        }
      }
    }
  ]
}
```

---

## Additional AWS Documentation References

| Topic | URL |
|-------|-----|
| IAM Security Best Practices | https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html |
| SCP Examples | https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html |
| Control Tower Controls | https://docs.aws.amazon.com/controltower/latest/controlreference/mandatory-controls.html |
| S3 Security Best Practices | https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html |
| Root User Best Practices | https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html |
| Permissions Boundaries | https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html |
| IAM Access Analyzer | https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html |

---

*Generated from aws-iam-permissions-guardrails repository + AWS Official Documentation*
