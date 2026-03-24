# litellm 1.82.8 Supply Chain Attack — AWS Impact Advisory

> **Security Advisory**: The `litellm==1.82.8` PyPI package contains a malicious credential-stealing payload that executes automatically on every Python startup. This repository provides an AWS environment scanner to detect exposure.

## Overview

The `litellm==1.82.8` wheel on PyPI contains `litellm_init.pth` (34,628 bytes) — a malicious `.pth` file that Python executes automatically on interpreter startup via the [site module](https://docs.python.org/3/library/site.html). No `import litellm` is required.

The payload is double base64-encoded, collects credentials from the host (AWS, SSH, Kubernetes, GCP, Azure, Docker, shell history, crypto wallets), encrypts them with AES-256 + RSA-4096, and exfiltrates to `models.litellm.cloud`.

**Original report**: [GitHub Issue #24512](https://github.com/BerriAI/litellm/issues/24512) by @isfinne  
**LiteLLM team response**: [GitHub Issue #24518](https://github.com/BerriAI/litellm/issues/24518)  
**GitHub Pages**: https://danielodeter.github.io/litellm-supply-chain-advisory/

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

## AWS Environment Scanner

This repository includes a CloudFormation template that deploys a Lambda-based scanner across your AWS environment.

### What Gets Scanned

| Service | What it checks |
|---------|---------------|
| Lambda | Env vars, container images, layers referencing litellm |
| ECR | Image tags referencing litellm; images pushed after 2026-03-24 |
| ECS | Task definition container images and env vars |
| CodeBuild | Inline buildspecs installing litellm, especially 1.82.8 |
| EC2 | SSM Run Command searches for `litellm_init.pth` on running instances |
| CloudTrail | IAM modifications (CreateUser, CreateAccessKey, etc.) after 2026-03-24 |
| GuardDuty | Credential exfiltration findings since compromise date |

### Deploy

```bat
cd scanner
deploy.bat your@email.com
```

The stack triggers an immediate scan on deploy, schedules daily re-scans via EventBridge, and optionally emails results via SNS.

**Manual invoke after deploy:**
```bash
aws lambda invoke --function-name litellm-environment-scanner --payload '{}' scan_results.json && cat scan_results.json
```

<details>
<summary>📋 CloudFormation Parameters & Outputs</summary>

**Parameters:**
- `NotificationEmail` — optional email address for SNS scan result notifications

**Outputs:**
- `ScannerFunctionName` — Lambda function name
- `ScanResultsTopicArn` — SNS topic ARN
- `ManualInvokeCommand` — ready-to-run CLI invoke command

**Resources created:**
- Lambda function (Python 3.12, 5-min timeout, 256MB)
- IAM role with least-privilege read-only permissions
- SNS topic for notifications
- EventBridge rule for daily scheduled scans
- CloudFormation custom resource for immediate scan on deploy

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
<summary>☁️ AWS Impact by Environment</summary>

| Environment | Severity | What's at risk |
|-------------|----------|----------------|
| EC2 Instances | 🔴 CRITICAL | Instance role credentials via IMDS |
| ECS / EKS Containers | 🔴 CRITICAL | Task/pod role credentials — every container from a compromised image |
| Lambda (container image) | 🟠 HIGH | Execution role credentials from env vars |
| CodeBuild | 🟠 HIGH | `AWS_*` env vars injected by the pipeline |
| Developer laptops | 🟠 HIGH | Long-term IAM keys from `~/.aws/credentials` |
| SageMaker | 🟠 HIGH | Execution role credentials |
| Elastic Beanstalk | 🟡 MEDIUM | Instance profile credentials |

**IMDS note**: The malware explicitly fetches the IMDSv2 token before calling the credentials endpoint. IMDSv2 alone is not a mitigation.

</details>

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
