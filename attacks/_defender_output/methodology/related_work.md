# Related Work — Detection Tool Comparison

> Status: skeleton — full content is Phase 1 deliverable (~1 h).

## 1. Selection criteria

## 2. Tools reviewed

### 2.1 Cloudsplaining (Salesforce)
### 2.2 Prowler
### 2.3 Datadog CloudSIEM out-of-box rules
### 2.4 Sigma HQ cloud category rules
### 2.5 CIS AWS Foundations Benchmark v3.0

## 3. Coverage matrix

Template:

| Path | Cloudsplaining | Prowler | Datadog | Sigma | CIS | PathTriage primitive |
|---|---|---|---|---|---|---|
| P1 (PassRole+RunInstances) | | | | | | 01 |
| P2 (IMDS SSRF) | | | | | | 01 |
| P3 (CreatePolicyVersion) | | | | | | 03 |
| P4 (AssumeRole Chain) | | | | | | 05 |
| P5 (AttachPolicy) | | | | | | 02 |
| P6 (Instance Profile Abuse) | | | | | | 01 |
| P7 (Lambda env-var theft) | | | | | | 04 |
| P8 (S3 credential harvest) | | | | | | 04 |

Cell values: `detect` / `miss` / `partial` (with reference).

## 4. Coverage aggregation

## 5. What PathTriage adds beyond each baseline
