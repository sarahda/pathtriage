# Chapter 1 — Statistics Notes (Supporting Evidence)

**Purpose**: Precise figures with citations for use in Chapter 1 §1.1.2
(pattern) and §1.3 (timeliness). These are supporting evidence, not
opening hooks — see `chapter1_breach_notes.md` for the case studies
that open the chapter.

**Author**: Tessa Moon, 2026-07-19  
**Consumed by**: `report/chapter1_motivation.md`

---

## Rule for using these numbers

Every statistic in the report gets a citation. No number goes into a
sentence without a footnote. Where sources disagree, use the primary
source (Verizon, IBM, Flexera, ISC² are all first-party).

Where multiple industry reports say the same thing (e.g., "stolen
credentials are the leading initial vector"), pick **one** to cite and
paraphrase; do not stack citations.

---

## Verizon Data Breach Investigations Report 2024 (DBIR 2024)

**Publisher**: Verizon Business, 17th annual edition, published May 2024.  
**URL**: https://www.verizon.com/business/resources/reports/dbir/  
**Scope**: 30,458 real-world security incidents, 10,626 confirmed data
breaches, 94 countries — the largest confirmed-breach corpus in the
report's history.

### Key figures (with citation)

- **Stolen credentials as initial vector — 24% of breaches** in 2023 (the
  data year of DBIR 2024). Source: Verizon 2024 DBIR, page 18, Figure:
  "Top Action varieties in breaches".
  Use this for §1.1.2 (chain pattern) and §1.3 (why now).

- **31% of breaches over the past decade** involved stolen credentials
  (cumulative). Source: Verizon 2024 DBIR, executive summary.

- **77% of Basic Web Application Attacks** involved stolen credentials.
  Source: Verizon 2024 DBIR, page 40. Use this to argue that
  cloud-authenticated attack surface (SaaS, cloud consoles) is
  disproportionately credential-driven.

- **68% of breaches involved a non-malicious human element** (error,
  social engineering). Source: Verizon 2024 DBIR, page 8. Complement to
  the credential figure — humans are the credential surface.

- **14% of breaches involving credentials began with phishing**. Source:
  Verizon 2024 DBIR, page 40.

### Recommended paragraph structure using DBIR

> "Verizon's 2024 Data Breach Investigations Report identifies stolen
> credentials as the initial access vector in 24% of confirmed breaches
> analysed [Verizon, 2024, p. 18], the largest single category. Across
> the past decade, 31% of all breaches began with credential
> compromise [ibid.]. In Basic Web Application Attacks — the category
> that most closely matches cloud-authenticated services — the figure
> rises to 77% [ibid., p. 40]."

Do not include multiple restatements of the same number in different
sections. Reference DBIR once per subsection maximum.

---

## IBM Cost of a Data Breach Report 2024

**Publisher**: IBM, 19th annual edition, published July 2024.  
**Report methodology**: 604 organisations, 3,556 interviewees globally.  
**URL**: https://www.ibm.com/security/data-breach

### Key figures (with citation)

- **Global average breach cost: USD 4.88 million** in 2024. Source: IBM
  Cost of a Data Breach Report 2024, press release. Represents a 10%
  increase from 2023 (USD 4.45M) — largest year-over-year increase since
  the pandemic.

- **Public cloud breaches: USD 5.17 million** average — most expensive
  breach type. Source: IBM 2024 report. Use for §1.3 (cloud-specific
  costs are higher than average).

- **Multi-environment breaches: >USD 5 million** average, 283 days to
  identify and contain. Source: IBM 2024. Use for §1.3 (multi-cloud is
  slower to detect and more expensive).

- **Stolen credentials as initial vector: 16% of breaches**, average cost
  **USD 4.81 million**. Source: IBM 2024, page 13. Slightly different
  methodology from Verizon (IBM uses different sampling), so numbers
  differ from Verizon's 24%. Cite both, note the methodology difference.

- **Compromised credentials take 292 days on average to identify and
  contain** — the longest of any attack vector. Source: IBM 2024.
  Use for §1.1.2 (chain-level detection is slow).

- **AI/automation extensive deployment reduces breach cost by USD 2.2M
  on average**. Source: IBM 2024. Use for §1.3 (automation is
  economically justified for defenders).

- **Healthcare breach average: USD 9.77 million** — 14th consecutive year
  as the costliest sector. Source: IBM 2024. Optional — use only if
  Chapter 1 makes an industry-vertical argument.

### Recommended paragraph structure using IBM

> "The IBM Cost of a Data Breach Report 2024 places the global average
> cost of a breach at USD 4.88 million, a 10% year-on-year increase
> [IBM, 2024]. Breaches involving public cloud specifically averaged
> USD 5.17 million, and multi-environment breaches — those spanning
> public cloud, private cloud, and on-premises — took a median 283 days
> to identify and contain [ibid.]. Breaches beginning with compromised
> credentials took the longest across all initial vectors, at 292 days,
> underscoring the operational cost of undetected identity paths."

---

## Flexera 2024 State of the Cloud Report

**Publisher**: Flexera, 13th annual edition, published March 2024.  
**Methodology**: 753 IT professionals and executive decision-makers,
surveyed Q4 2023.  
**URL**: https://www.flexera.com/blog/finops/cloud-computing-trends-flexera-2024-state-of-the-cloud-report/

### Key figures (with citation)

- **89% of organisations use multi-cloud** in 2024, up from 87% in 2023.
  Source: Flexera 2024 State of the Cloud, executive summary.
  **This is the anchor statistic for §1.3.1.**

- **73% use hybrid cloud** (public + private together). Source: Flexera
  2024.

- **AWS significant workload usage: 49%**; **Azure: 45%**; **GCP: 21%**.
  Source: Flexera 2024. Use for §1.3 to justify the AWS + Azure focus
  in PathTriage.

- **61% of large enterprises use multi-cloud security tools**. Source:
  Flexera 2024. Use for §1.2 (gap): existing multi-cloud security tools
  are cost-optimisation-focused, not chain-analysis-focused.

- **Nearly half of workloads and data now in public cloud**. Source:
  Flexera 2024 executive summary. Use for §1.3.

### Recommended paragraph structure using Flexera

> "Multi-cloud adoption is now near-saturation: Flexera's 2024 State
> of the Cloud Report shows 89% of surveyed organisations operate
> across multiple cloud providers, up from 87% the prior year [Flexera,
> 2024]. AWS and Azure remain the dominant providers with 49% and 45%
> significant-workload usage respectively; Google Cloud Platform
> accounts for 21%. Security tooling has not kept pace: 61% of large
> enterprises deploy multi-cloud FinOps or security tools, but
> comparative attack-path analysis across providers remains a research
> gap [ibid.]."

---

## ISC² 2024 Cybersecurity Workforce Study

**Publisher**: ISC², published September 2024 (initial findings),
full report October 2024.  
**Methodology**: 15,000+ cybersecurity professionals surveyed globally.  
**URL**: https://www.isc2.org/Insights/2024/10/ISC2-2024-Cybersecurity-Workforce-Study

### Key figures (with citation)

- **Global cybersecurity workforce gap: 4.8 million professionals** in
  2024 — a 19% year-on-year increase. Source: ISC² 2024 Cybersecurity
  Workforce Study.
  **This is the anchor statistic for §1.3.3 (resource constraints).**

- **Global active cybersecurity workforce: 5.5 million** (a 0.1%
  year-on-year increase — effectively flat). Source: ISC² 2024.

- **Workforce gap represents ~47% shortfall** relative to demand. Source:
  ISC² 2024, derived.

- **59% of cybersecurity professionals report that skills gaps have
  impaired their ability to secure their organizations**. Source: ISC²
  2024. Use for §1.3.3 (automation is not optional — the humans do not
  exist to do it manually).

- **58% of organizations say skills gaps put them at significant risk**.
  Source: ISC² 2024. Most critical gaps identified: **cloud security**,
  risk assessment, security engineering.

- **74% of security professionals call the current threat landscape the
  most challenging they've faced in five years**. Source: ISC² 2024.

### Recommended paragraph structure using ISC²

> "The economic case for automation-based triage is reinforced by
> workforce data. The ISC² 2024 Cybersecurity Workforce Study reports a
> global workforce gap of 4.8 million professionals — a 19% year-on-year
> increase, while the active workforce grew only 0.1% [ISC², 2024]. The
> most critical skills shortages identified are in cloud security,
> matching the trajectory of the multi-cloud adoption reported by
> Flexera [ibid.]. In this environment, manual review of enumeration
> tool output at scale is not merely inefficient — it is
> operationally infeasible."

---

## Additional supporting sources (optional — use if space permits)

### Palo Alto Unit 42 2024 Incident Response Report

Cloud identity misconfiguration remains among the top attack vectors
across Unit 42's IR engagements. Data not restated here (specific
percentages proprietary), but cite in §1.1.2 as corroborating
evidence for the chain-composition pattern.

URL: https://www.paloaltonetworks.com/unit42

### Google Threat Horizons 2024

Cross-cloud identity attacks (including OAuth cross-tenant abuse) up
year-on-year. Cite in §1.3 alongside Midnight Blizzard case study.

URL: https://cloud.google.com/blog/products/identity-security/threat-horizons-report-h1-2024

---

## Recommended aggregate paragraph for §1.3 opening

If Chapter 1 §1.3 opens with a single "why now" paragraph before
subsections, this is a candidate structure:

> "Three trends converge to make ranked cloud attack-path discovery an
> acute research problem in 2026. Multi-cloud is now the default
> operating environment — 89% of organizations run across multiple cloud
> providers [Flexera, 2024]. Attack costs are rising fastest in cloud
> settings — the average breach involving public cloud costs USD 5.17
> million, and multi-environment breaches take 283 days to detect [IBM,
> 2024]. And the security workforce needed to review enumeration output
> at scale simply does not exist — the 4.8 million-person global
> workforce gap represents a 19% year-on-year increase against a
> workforce that grew 0.1% [ISC², 2024]. Automation-based triage is not
> optimisation; it is precondition."

Adjust word count for report length constraint.

---

## Do NOT use in Chapter 1

- **Verizon DBIR 2025** — post-dates the thesis project timeline. Cite
  only if a specific 2024 number is not available.
- **IBM 2025 Cost of Data Breach** — same reason.
- **Flexera 2025 / 2026 reports** — same reason. Anchor on 2024
  edition throughout for consistency.
- **Krebs on Security** — good for breach case narrative in
  `chapter1_breach_notes.md`, but not for statistics section.
- **Vendor blogs** citing DBIR numbers second-hand — always cite
  Verizon directly, not Skyhigh, SpyCloud, etc.

---

## Bibliography-ready citation blocks

Copy-paste ready for the report's bibliography (IEEE-style, adjust if
supervisor prefers APA):

```
[N] Verizon Business, "2024 Data Breach Investigations Report,"
    Verizon Communications Inc., May 2024. [Online]. Available:
    https://www.verizon.com/business/resources/reports/dbir/

[N] IBM Security, "Cost of a Data Breach Report 2024,"
    IBM Corporation, July 2024. [Online]. Available:
    https://www.ibm.com/security/data-breach

[N] Flexera, "Flexera 2024 State of the Cloud Report,"
    Flexera Inc., March 2024. [Online]. Available:
    https://www.flexera.com/stateofthecloud

[N] ISC2, "2024 ISC2 Cybersecurity Workforce Study,"
    ISC2 Inc., October 2024. [Online]. Available:
    https://www.isc2.org/research
```
