# Adversarial Evasion Framework

> Status: skeleton — full content is Phase 1 deliverable (~0.5 h).

## 1. Threat model

### 1.1 Attacker capability assumed
### 1.2 Attacker knowledge of detection (blind / graybox / whitebox)
### 1.3 Out-of-scope evasion classes

## 2. Evasion cost taxonomy

- **Capability cost**: what additional attacker capability is required
- **Operational cost**: how much slower/noisier the attack becomes
- **Detection-elsewhere cost**: what other signals the evasion introduces

## 3. Per-primitive evasion template

Each primitive's `adversarial_evasion.md` follows this structure:

1. **Baseline signature** (what the primitive detects)
2. **Evasion candidates** (2–4 realistic evasions)
3. **Cost per evasion** (three-cost tuple)
4. **Residual detection** (what still catches the evaded attack)

## 4. Consolidated table

To be produced in Phase 4 alongside evaluation results.
