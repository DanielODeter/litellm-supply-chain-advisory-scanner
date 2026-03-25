# litellm Supply Chain Attack — AWS Resource Scanner

> ⚠️ **Disclaimer**: This is a sample. Users are responsible for ensuring that the code herein is compliant with your own security and compliance standards.

> Detect exposure to the litellm 1.82.8 PyPI supply chain compromise across your AWS environment.

This repository provides a CloudFormation-deployable AWS Resource Scanner to check whether your AWS environment was exposed to the `litellm==1.82.8` supply chain compromise. It supports both single-account and AWS Organizations deployments.

For full details of the attack, see the original advisory. In summary: the package contains a malicious `litellm_init.pth` file that executes automatically on every Python startup, collects credentials (AWS, SSH, Kubernetes, Docker, shell history), and exfiltrates them to an attacker-controlled domain.

**Original advisory**: [GitHub Issue #24512](https://github.com/BerriAI/litellm/issues/24512) by @isfinne  
**LiteLLM team response**: [GitHub Issue #24518](https://github.com/BerriAI/litellm/issues/24518)  
**GitHub Pages**: https://danielodeter.github.io/litellm-supply-chain-advisory-scanner/

---

## 🚨 Immediate Actions

If `litellm==1.82.8` was installed anywhere with AWS credentials present:

1. `pip uninstall litellm` and delete `litellm_init.pth` from `site-packages/`
2. **Rotate ALL IAM access keys** — IAM console → Users → Security credentials
3. Rotate SSH keys, Docker credentials, and any secrets in environment variables
4. Block `models.litellm.cloud` at network/firewall level
5. Check CloudTrail for IAM modifications after 2026-03-24
6. Rebuild any Docker images that included this version

---

## IOCs

| Type | Value |
|------|-------|
| Malicious file | `litellm_init.pth` in `site-packages/` |
| File size | 34,628 bytes |
| SHA-256 | `ceNa7wMJnNHy1kRnNCcwJaFjWX3pORLfMh7xGL8TUjg` |
| Exfil domain | `models.litellm.cloud` (NOT the official `litellm.ai`) |
| Exfil endpoint | `POST https://models.litellm.cloud/` with header `X-Filename: tpcp.tar.gz` |
| Affected version | `litellm==1.82.8` |

---

## AWS Resource Scanner

Two deployment models are available depending on your AWS environment.

### Deployment Models

| Feature | **Single Account** | **AWS Organizations** |
|---------|-------------------|----------------------|
| **Template** | `scanner-single-account.yaml` | `scanner-org.yaml` |
| **When to use** | One account, dev/test, quick scan | Multiple accounts, production |
| **Deploy from** | Any account | Management account only |
| **Results** | Local S3 bucket | Central S3 bucket, all accounts write here |
| **Notifications** | Per-account SNS | Consolidated org-wide SNS |
| **IAM required** | Single account role | StackSets service-managed permissions |

### What Gets Scanned (both models)

| Service | What it checks | Limitations |
|---------|---------------|-------------|
| Lambda | Env vars, container images, layers referencing litellm | Only checks functions visible to the scanner role; does not inspect layer zip contents |
| ECR | Image tags referencing litellm; images pushed after 2026-03-24 | Does not inspect image contents or scan for the malicious file inside layers |
| ECS | Task definition container images and env vars | Only active task definitions; does not check running tasks or Fargate sidecar containers |
| CodeBuild | Inline buildspecs installing litellm, especially 1.82.8 | Only checks inline buildspecs; external buildspec files (e.g. in S3 or CodeCommit) are not scanned |
| EC2 | SSM Run Command searches for `litellm_init.pth` on running instances | Requires SSM Agent installed and `AmazonSSMManagedInstanceCore` attached to the instance role; instances without SSM will not be checked |
| CloudTrail | IAM modifications (CreateUser, CreateAccessKey, etc.) after 2026-03-24 | Limited to the last 90 days of CloudTrail event history; only checks a subset of IAM event types |
| GuardDuty | Credential exfiltration findings since compromise date | Requires GuardDuty to be enabled in the account and region; findings may take time to appear |

---

<details>
<summary>🏢 Option 1: Single Account Deployment</summary>

**When to use:**
- ✅ Scanning a single AWS account
- ✅ Development or test environments
- ✅ Quick one-off scan

```bat
cd scanner
deploy.bat single your@email.com your-aws-profile
```

Triggers an immediate scan on deploy, schedules daily re-scans, and optionally emails results via SNS.

**Manual invoke:**
```bash
aws lambda invoke --function-name litellm-scanner-litellm-scanner-single --payload '{}' results.json
```

**Parameters:**
- `NotificationEmail` — optional SNS email
- `ResultsBucketName` — optional S3 bucket name (auto-generated if blank)

**Outputs:** `ScannerFunctionName`, `ResultsBucketName`, `ScanResultsTopicArn`, `ManualInvokeCommand`

</details>

<details>
<summary>🏛️ Option 2: AWS Organizations Deployment (Recommended for multi-account)</summary>

**When to use:**
- ✅ AWS Organizations with multiple member accounts
- ✅ Production environments
- ✅ Need consolidated results across all accounts

**Prerequisites:**
- AWS Organizations enabled
- CloudFormation StackSets with service-managed permissions enabled
- Must be deployed from the **management account**

**Enable trusted access for StackSets (one-time):**
```bash
aws organizations enable-aws-service-access \
  --service-principal stacksets.cloudformation.amazonaws.com
```

**Deploy:**
```bat
cd scanner
deploy.bat org o-xxxxxxxxxx your@email.com your-mgmt-profile "us-east-1,us-west-2"
```

This deploys:
1. Central S3 bucket in the management account — all member accounts write results here
2. StackSet that automatically deploys the member scanner to every account in the org
3. Aggregator Lambda that consolidates all results daily
4. SNS topic for org-wide consolidated notifications

**Manual aggregate:**
```bash
aws lambda invoke --function-name litellm-aggregator-litellm-scanner-org --payload '{}' aggregated.json
```

**Check StackSet deployment status:**
```bash
aws cloudformation list-stack-instances \
  --stack-set-name litellm-member-scanner \
  --query 'Summaries[*].{Account:Account,Region:Region,Status:Status}' \
  --output table
```

**Parameters:**
- `OrganizationId` — your org ID (e.g. `o-xxxxxxxxxx`)
- `NotificationEmail` — optional consolidated SNS email
- `DeploymentRegions` — comma-delimited regions (default: `us-east-1`)

**Outputs:** `CentralResultsBucket`, `AggregatorFunctionName`, `ConsolidatedTopicArn`, `ManualAggregateCommand`

</details>

---

<details>
<summary>🔍 Manual Detection Commands</summary>

**Check for the malicious file:**
```bash
# Linux / macOS / container
find / -name "litellm_init.pth" 2>/dev/null

# Windows
dir /s /b "%USERPROFILE%\litellm_init.pth" 2>nul
```

**Check CloudTrail for post-compromise IAM activity:**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time 2026-03-24T00:00:00Z
```

**Check GuardDuty:**
```bash
DETECTOR=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty list-findings \
  --detector-id $DETECTOR \
  --finding-criteria '{"Criterion":{"type":{"Eq":["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"]},"updatedAt":{"Gte":1742774400000}}}'
```

**SSM bulk check across all EC2 instances:**
```bash
aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --targets "Key=tag:Environment,Values=prod" \
  --parameters 'commands=["find / -name litellm_init.pth 2>/dev/null && pip show litellm 2>/dev/null"]'
```

</details>

<details>
<summary>☁️ AWS Impact by Resource</summary>

| Resource | Severity | What's at risk | Checked by scanner |
|----------|----------|----------------|--------------------|
| EC2 Instances | 🔴 CRITICAL | Instance role credentials via IMDS | ✅ SSM Run Command |
| ECS / EKS Containers | 🔴 CRITICAL | Task/pod role credentials — every container from a compromised image | ✅ ECS task definitions |
| Lambda (container image) | 🟠 HIGH | Execution role credentials from env vars | ✅ Lambda functions + layers |
| CodeBuild | 🟠 HIGH | `AWS_*` env vars injected by the pipeline | ✅ Buildspecs + env vars |
| Developer laptops | 🟠 HIGH | Long-term IAM keys from `~/.aws/credentials` | ❌ Local only |
| SageMaker | 🟠 HIGH | Execution role credentials | ❌ Not yet covered |
| Elastic Beanstalk | 🟡 MEDIUM | Instance profile credentials | ✅ Via SSM if agent installed |

**IMDS note**: The malware explicitly fetches the IMDSv2 token before calling the credentials endpoint. IMDSv2 alone is not a mitigation.

</details>

<details>
<summary>💰 Scanner Costs</summary>

All costs are based on daily scans. Most services fall within the AWS Free Tier at this usage level — the KMS CMK is the only fixed cost.

**Cost per account (monthly)**

| Service | Cost | Notes |
|---------|------|-------|
| Lambda | ~$0.00 | ~300s/day at 256MB, within free tier |
| EventBridge | ~$0.00 | Scheduling is free |
| S3 | ~$0.00 | ~2KB per scan result, negligible |
| SNS | ~$0.00 | Within 1,000 free email deliveries/month |
| KMS CMK | $1.00 | 1 CMK per account, flat monthly fee |
| **Per account total** | **~$1.00/month** | |

**Org deployment adds (management account only)**

| Service | Cost | Notes |
|---------|------|-------|
| KMS CMK (SNS) | $1.00 | 1 additional CMK for consolidated SNS topic |
| Aggregator Lambda | ~$0.00 | Within free tier |
| S3 (central bucket) | ~$0.00 | Negligible storage |
| **Org overhead total** | **~$1.00/month** | One-time regardless of account count |

**Examples**

| Deployment | Accounts | Est. Monthly Cost |
|------------|----------|-------------------|
| Single account | 1 | ~$1.00 |
| Org deployment | 1 | ~$2.00 (member CMK + org overhead) |
| Org deployment | 10 | ~$11.00 |
| Org deployment | 100 | ~$101.00 |

> Costs will increase if accounts have large numbers of Lambda functions, ECS task definitions, or EC2 instances that extend scan duration beyond the free tier compute threshold. Use the [AWS Pricing Calculator](https://calculator.aws) for a precise estimate based on your environment.

</details>

---

<details>
<summary>🛡️ Prevention Going Forward</summary>

- Pin exact package versions and verify hashes: `pip hash`
- Use [AWS CodeArtifact](https://aws.amazon.com/codeartifact/) as a private PyPI proxy
- Enforce IMDSv2 only (`HttpTokens: required`) on all EC2 instances
- Apply least-privilege IAM — no `iam:*` on compute roles
- Enable GuardDuty in all accounts and regions
- Scan ECR images with Amazon Inspector
- Enable AWS Config for continuous compliance monitoring

</details>

---

<details>
<summary>📜 License</summary>

This repository is provided under the MIT-0 License for defensive and informational purposes only.

</details>
