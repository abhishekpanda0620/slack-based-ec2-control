# Slack → Lambda → EC2 Control

Control a development EC2 instance from Slack via slash commands (`/ec2 start | stop | status`).

---

## Architecture

```
Slack /ec2 <command>
      │
      ▼
Lambda Function URL  (AuthType: NONE, HMAC-verified in code)
      │
      ▼
Lambda: control_ec2_from_slack   (Python 3.14)
      │
      ▼
EC2 Instance  (us-east-1)
```

**Why Function URL (not API Gateway):** Free (API Gateway charges per request beyond free tier). Slack auth is handled in-code via HMAC-SHA256 signature verification using Slack's signing secret.

---

## Current Deployed Resources

| Resource | Value |
|---|---|
| **AWS Account** | `<YOUR_AWS_ACCOUNT_ID>` |
| **Region** | `us-east-1` |
| **Lambda function name** | `control_ec2_from_slack` |
| **Lambda handler** | `app.lambda_handler` |
| **Lambda runtime** | Python 3.14 |
| **Lambda execution role** | `control_ec2_from_slack-role-<suffix>` |
| **Lambda Function URL** | `<YOUR_FUNCTION_URL>` |
| **Function URL Auth type** | `NONE` |
| **EC2 Instance (dev)** | `<YOUR_INSTANCE_ID>` |
| **Slack slash command** | `/ec2` |

---

## Environment Variables (on Lambda)

| Key | Required | Notes |
|---|---|---|
| `AWS_REGION_NAME` | ✅ | `us-east-1`. Named this way because `AWS_REGION` is reserved by Lambda runtime. |
| `INSTANCE_ID` | ✅ | Your EC2 instance ID (e.g. `i-0123456789abcdef0`) |
| `SLACK_SIGNING_SECRET` | ✅ | From Slack app → Basic Information → App Credentials → **Signing Secret** (NOT Verification Token) |
| `ALLOWED_TEAM_IDS` | optional | Comma-separated. Restricts which Slack workspace(s) can invoke. |
| `ALLOWED_CHANNEL_IDS` | optional | Comma-separated. Restricts which channel(s). |
| `ALLOWED_USER_IDS` | optional | Comma-separated. Restricts which user(s). Find your Slack user ID in your profile → ⋮ → Copy member ID. |

> **Note:** `SLACK_SIGNING_SECRET` is stored as a Lambda environment variable. Treat it as sensitive — do not log it or commit it to source control.

---

## IAM Setup

### Lambda execution role inline policy: `EC2ControlDevInstance`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ControlDevInstance",
      "Effect": "Allow",
      "Action": ["ec2:StartInstances", "ec2:StopInstances"],
      "Resource": "arn:aws:ec2:us-east-1:<YOUR_AWS_ACCOUNT_ID>:instance/<YOUR_INSTANCE_ID>"
    },
    {
      "Sid": "DescribeInstancesInRegion",
      "Effect": "Allow",
      "Action": "ec2:DescribeInstances",
      "Resource": "*",
      "Condition": {
        "StringEquals": {"ec2:Region": "us-east-1"}
      }
    }
  ]
}
```

Plus the default `AWSLambdaBasicExecutionRole` for CloudWatch Logs.

### Function URL resource-based policy (2 statements — BOTH required as of Oct 2025)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FunctionURLAllowPublicAccess",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "lambda:InvokeFunctionUrl",
      "Resource": "arn:aws:lambda:us-east-1:<YOUR_AWS_ACCOUNT_ID>:function:control_ec2_from_slack",
      "Condition": {
        "StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}
      }
    },
    {
      "Sid": "FunctionURLAllowPublicInvoke",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "lambda:InvokeFunction",
      "Resource": "arn:aws:lambda:us-east-1:<YOUR_AWS_ACCOUNT_ID>:function:control_ec2_from_slack"
    }
  ]
}
```

> **Gotcha:** Since October 2025, AWS requires **both** `lambda:InvokeFunctionUrl` AND `lambda:InvokeFunction` on the resource policy. The console's "create function URL" adds both automatically; `update-function-url-config` via CLI does not — you must add the second one manually with `aws lambda add-permission`.

---

## Slack App Setup

1. Create app at https://api.slack.com/apps (From scratch)
2. **Basic Information** → copy **Signing Secret** into Lambda env var
3. **Slash Commands** → Create new command:
   - **Command:** `/ec2`
   - **Request URL:** *(your Lambda Function URL)*
   - **Short Description:** `Control EC2 instance`
   - **Usage Hint:** `start | stop | status`
4. **Install App** → workspace

### Slack IDs currently in use
- Team ID: *(in `ALLOWED_TEAM_IDS` env var)*
- Channel ID: *(in `ALLOWED_CHANNEL_IDS` env var)*
- Authorized users: *(in `ALLOWED_USER_IDS` env var)*

---

## Lambda Function Code

Current code lives at: **`app/lambda_handler.py`** (in this repo)

Lambda handler entry point: **`app.lambda_handler`** (set this in the Lambda console → Runtime settings → Handler)

### Security features
- HMAC-SHA256 signature verification with constant-time comparison
- 5-minute replay window
- Request size cap (4 KB)
- Strict command allow-list (`start`, `stop`, `status`)
- Optional team/channel/user allow-lists (fail closed)
- Sanitized error messages to Slack; full traces to CloudWatch only
- Base64-encoded bodies (Lambda URL default) are decoded transparently before verification

### Behavior features
- **State-aware** start/stop: checks instance state before acting

  | Current State | `/ec2 start` | `/ec2 stop` |
  | --- | --- | --- |
  | `stopped` | ✅ starts it | "already stopped — no action" |
  | `running` | "already running — no action" | ✅ stops it |
  | `pending` | "already starting up — wait" | ⚠️ "wait until running" |
  | `stopping` | ⚠️ "wait until stopped" | "already stopping — wait" |
  | `terminated` | ❌ "terminated, cannot start" | ❌ "terminated" |
  | other | ⚠️ generic "cannot act" | ⚠️ generic "cannot act" |

- **Response visibility:**
  - `start` / `stop` **success** messages: posted to channel (`in_channel`, visible to everyone)
  - All other responses (errors, warnings, status): ephemeral (visible only to the invoker)
- Emoji status indicators: 🟢 running, 🔴 stopped, ⏳ transitioning (pending/stopping/shutting-down), 💀 terminated, ❓ unknown
- Audit logs for every action (who, what, when, where)

---

## Deployment (current manual process)

```bash
# Zip and update Lambda code (run from repo root)
zip -j function.zip app/lambda_handler.py
aws lambda update-function-code \
  --function-name control_ec2_from_slack \
  --region us-east-1 \
  --zip-file fileb://function.zip
```

> **Note:** `-j` (junk paths) keeps the file at the zip root so Lambda resolves the handler as `lambda_handler.lambda_handler`. If you keep directory structure, use `zip -r function.zip app/` and set handler to `app.lambda_handler`.

---

## Debugging Commands

```bash
# Live tail logs
aws logs tail /aws/lambda/control_ec2_from_slack --follow --since 5m

# Check Function URL config
aws lambda get-function-url-config \
  --function-name control_ec2_from_slack \
  --region us-east-1

# Check resource policy (both permissions should be present)
aws lambda get-policy \
  --function-name control_ec2_from_slack \
  --region us-east-1 \
  --query 'Policy' --output text | jq .

# Check env vars
aws lambda get-function-configuration \
  --function-name control_ec2_from_slack \
  --region us-east-1 \
  --query 'Environment.Variables'

# Direct invoke (bypasses URL auth layer)
aws lambda invoke \
  --function-name control_ec2_from_slack \
  --region us-east-1 \
  --payload '{"body":"text=status","headers":{}}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/out.json && cat /tmp/out.json

# Test URL (unsigned — should return 401 Unauthorized, NOT 403)
curl -i -X POST '<YOUR_FUNCTION_URL>' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'text=status'
```

### Expected responses

| Test | Expected |
|---|---|
| Unsigned curl to Function URL | `HTTP 401` + `{"text": ":x: Unauthorized."}` |
| `aws lambda invoke` (direct) | `StatusCode: 200`, body with `:x: Unauthorized.` (no signature headers) |
| `/ec2 status` from Slack | 🟢/🔴 emoji + instance state |

---

## Common Issues & Fixes

| Symptom | Cause | Fix |
|---|---|---|
| `/ec2 failed because the app did not respond` | Slack timeout (>3s) or Lambda crash | `aws logs tail` while reproducing |
| `HTTP 403 AccessDeniedException` on curl | Missing `lambda:InvokeFunction` on resource policy (post-Oct 2025 change) | `aws lambda add-permission` with `lambda:InvokeFunction` |
| `Slack signature verification failed` in logs | Wrong `SLACK_SIGNING_SECRET` env var (likely copied Verification Token instead) | Re-copy from Slack → Basic Information → **Signing Secret** |
| `UnauthorizedOperation` from EC2 | Missing IAM policy on Lambda role | Attach `EC2ControlDevInstance` inline policy |
| No logs when `/ec2` runs | URL mismatch between Slack slash command and Function URL | Re-copy URL; **save** the slash command in Slack |
| Function URL edits greyed out | IAM lacks `lambda:UpdateFunctionUrlConfig` | Use CLI `aws lambda update-function-url-config` |

---

## Next Steps — Version Control & CI/CD (TODO)

**Goal:** Move Lambda to a Git repo with automated deployment.

### Open questions to resolve
1. **Repo host:** GitHub / GitLab / Bitbucket — *not yet decided*
2. **IaC tool:** Terraform / SAM / CDK / plain CLI script — *not yet decided*
3. **CI/CD:** auto-deploy on push to `main` — *not yet decided*

### Suggested repo structure

```
slack-ec2-control/
├── .github/workflows/deploy.yml       # CI/CD (if GitHub Actions)
├── infra/                             # IaC (Terraform/SAM/CDK)
│   ├── main.tf                        # Lambda, IAM, Function URL
│   └── variables.tf
├── app/
│   └── lambda_handler.py              # The handler code (entry point: app.lambda_handler)
├── tests/
│   └── test_lambda.py                 # Unit tests for signature verify, state logic
├── .gitignore
├── .env.example                       # Document required env vars (no secrets)
├── Makefile                           # make deploy / make test / make logs
└── README.md                          # ← This file
```

### Secrets handling

- Never commit `SLACK_SIGNING_SECRET` — set it directly in Lambda environment variables
- For CI/CD, store AWS credentials as repository secrets (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) — or use GitHub OIDC with an assumable role (preferred)

### Recommended for this scope: **Terraform**
- Full control over Lambda + IAM + Function URL + resource policy
- Handles the dual-permission issue properly
- Easy to add more dev instances or expand scope later

### Alternative: **AWS SAM**
- AWS-native, simpler for pure-Lambda projects
- `sam deploy` does everything in one command
- Less flexible than Terraform for non-serverless resources

---

## Enhancement Ideas (backlog)

- [ ] Support multiple EC2 instances (pass instance name/alias: `/ec2 start staging`)
- [ ] Auto-stop scheduler (CloudWatch Event Rule → Lambda) to turn off dev instance every night at 8pm
- [ ] Add `/ec2 uptime` command showing how long instance has been running
- [ ] Slack interactive button confirmation for `stop` (prevent fat-fingering)
- [ ] Lambda reserved concurrency = 5 (DoS protection)
- [ ] CloudWatch alarm on invocation spike (>20/min)
- [ ] Add unit tests (pytest) for signature verification and state-handling logic

---

## Reference Links

- [Slack signing secret verification](https://api.slack.com/authentication/verifying-requests-from-slack)
- [Lambda Function URL auth](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)
- [EC2 instance states](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html)

---

*Last updated: 2026-04-22*