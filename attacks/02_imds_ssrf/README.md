# Path 02 — IMDS SSRF Credential Theft

## Overview

A server-side request forgery (SSRF) flaw in an application running on an EC2
instance can be turned into AWS credential theft when the instance still allows
**IMDSv1** (token-less metadata access). The attacker never needs AWS
credentials to begin — only network reach to the vulnerable app. By coercing the
server into fetching `http://169.254.169.254/...`, the attacker reads the
instance role's temporary credentials and assumes its identity.

The point for the catalogue: neither the SSRF nor IMDSv1 is, on its own, the kind
of finding a permission-level audit would flag — one is an app bug, the other an
instance-metadata setting. The **path** is what converts a web bug into cloud
identity compromise.

## Attack Flow

```
  attacker (no AWS creds)
        |
        |  GET /fetch?url=http://169.254.169.254/.../security-credentials/
        v
  +-------------------------+        IMDSv1 (no token required)
  |  EC2: vulnerable Flask  | ---------------------------------+
  |  app  (SSRF in /fetch)  |                                  |
  +-------------------------+                                  v
        ^                                          169.254.169.254 (IMDS)
        |  role creds returned in HTTP body                    |
        +------------------------------------------------------+
        |
        v
  AccessKeyId / SecretAccessKey / Token  -->  boto3 session
        |
        +--> sts:GetCallerIdentity  (now = pathtriage-imds-instance-role)
        +--> s3:ListBuckets         (impact: the role's S3 read access)
```

## MITRE ATT&CK

- **T1090** — Proxy (the app is coerced into proxying requests to IMDS)
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API

## Prerequisites

- Baseline deployed (`environments/baseline`) exporting `vpc_id` and
  `public_subnet_id` (see note below).
- Network reach to the instance on TCP/5000.

> [!warning] Baseline outputs
> This scenario reads `data.terraform_remote_state.baseline.outputs.vpc_id`
> and `.public_subnet_id`. Path 1 only needed the low-priv user outputs, so if
> the baseline doesn't export the network IDs yet, add them to
> `environments/baseline/outputs.tf`:
> ```hcl
> output "vpc_id"           { value = aws_vpc.main.id }
> output "public_subnet_id" { value = aws_subnet.public.id }
> ```

## Lab Deployment

```bash
cd environments/scenarios/02_imds_ssrf
terraform init
terraform apply        # yes
terraform output scenario_summary
# Wait ~90s for user_data to install Flask and start the service.
```

## Attack Steps

1. Confirm the app is up: `curl http://<ip>:5000/`
2. Run the PoC against the app URL (no AWS creds needed):
   ```bash
   python3 attacks/02_imds_ssrf/exploit.py --target http://<ip>:5000
   ```
3. The script chains: SSRF → role discovery → credential exfiltration →
   `sts:GetCallerIdentity` → `s3:ListBuckets`.

## Expected Output

Captured in `verification_log.txt`. The terminal shows the discovered role
(`pathtriage-imds-instance-role`), the stolen `AccessKeyId`, the caller identity
resolving to the instance role, and a successful `s3:ListBuckets`.

## Vulnerable Configuration

```hcl
metadata_options {
  http_endpoint = "enabled"
  http_tokens   = "optional"   # IMDSv1 allowed — the metadata-side weakness
}
```

plus an app endpoint that fetches arbitrary user-supplied URLs with no
allow-list (`/fetch?url=`).

## Why This Works

IMDSv1 answers any local HTTP GET with no session token. An SSRF gives the
attacker a *local* request primitive on the instance, so the two combine: the
app makes the metadata request on the attacker's behalf and hands back the
role's short-lived credentials. IMDSv2 would break this — it requires a
`PUT`-issued token and a hop limit that a typical SSRF GET cannot satisfy.

## Defender Output *(deferred — W7)*

This path's extraction step (IMDS credential read) **converges** with Path 1 and
Path 5. Detection and mitigation are intentionally designed once across those
paths in W7 rather than duplicated per path:
- Detection: CloudTrail/GuardDuty `InstanceCredentialExfiltration`-style signal;
  role credentials used from an IP outside the instance.
- Mitigation: enforce IMDSv2 (`http_tokens = "required"`); SCP denying
  `ec2:RunInstances`/`ec2:ModifyInstanceMetadataOptions` with IMDSv1.

## Exploitability Score *(deferred — W5)*

Will be scored under the unified rubric once ≥5 paths exist.

## Status

- [x] Terraform vulnerable environment
- [x] PoC script (`exploit.py`)
- [ ] Verification log — capture on first clean run
- [ ] Defender output (deferred to W7 — shared IMDS convergence)
- [ ] Exploitability score (deferred to W5 — unified rubric)

## Cleanup

```bash
cd environments/scenarios/02_imds_ssrf && terraform destroy
```

## References

- AWS, "Use IMDSv2" (instance metadata service hardening)
- OWASP, Server Side Request Forgery
- Rhino Security Labs, AWS IAM privilege escalation methods
