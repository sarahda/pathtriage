# PathTriage

**Exploitability-Ranked IAM Attack-Path Discovery and Defender-Output Synthesis for AWS and Azure**

A Python tool that discovers IAM privilege escalation paths in AWS and Azure cloud environments, ranks them by exploitability using a defended metric, and generates defender output — detection queries and remediation policies — for each ranked path.

## Project Context

This is a Master's research project conducted within the UNSW COMP9301 (Term 2 2026) and COMP9302 (Term 3 2026) framework.

## Status

🚧 Work in progress — Week 1 of COMP9301

## Repository Structure

- `attacks/` — Attack path catalogue (PoC scripts, READMEs, MITRE mappings)
- `pathtriage/` — Core Python package (graph engine, scoring, defender output)
- `environments/` — Terraform lab configurations
- `docs/` — Documentation (architecture, evaluation protocol, reports)

## License

MIT — see [LICENSE](LICENSE)

## Responsible Use

This project includes proof-of-concept code for IAM attack paths intended for security research and defensive purposes. PoCs should only be run in isolated, intentionally vulnerable environments (e.g., CloudGoat scenarios). Do not run against production systems without explicit authorisation.