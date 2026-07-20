# Chapter 1 — Breach Case Study Notes

**Purpose**: Source material for Chapter 1 §1.1 opening. Each case is
reconstructed from public post-mortems, court filings, or vendor
threat-intelligence reports. Citations are inline; use these for the
final report's bibliography.

**Author**: Tessa Moon, 2026-07-19  
**Consumed by**: `report/chapter1_motivation.md`

---

## Case 1 — Capital One 2019 (AWS)

### Executive summary (2 sentences for opening)

In March 2019, a former AWS engineer named Paige Thompson exploited a
Server-Side Request Forgery (SSRF) vulnerability in a Capital One Web
Application Firewall to query the EC2 instance metadata service and
extract temporary IAM credentials attached to the WAF's instance role.
Those credentials — legitimate for the WAF's function but excessively
scoped — were used to enumerate and exfiltrate 106 million customer
records from over 700 S3 buckets before detection four months later.

### Timeline

| Date | Event | Source |
|---|---|---|
| 2019-03-22 | Attack begins | DOJ indictment |
| 2019-03-23 | Bulk of exfiltration completed | DOJ indictment |
| 2019-07-17 | Anonymous GitHub tipoff to Capital One | Krebs on Security |
| 2019-07-19 | Capital One confirms breach internally | Capital One 8-K |
| 2019-07-29 | FBI arrests Paige Thompson (aka "erratic") | DOJ press release |
| 2019-07-29 | Capital One public disclosure | Capital One 8-K |

Detection lag: **~4 months** from attack to internal confirmation.

### IAM chain reconstruction

The attack chain — the specific interpretation this thesis uses — is a
five-hop path where every individual permission is legitimate for the
principal that holds it, but the composition produces catastrophic
capability:

```
STEP 0. Attacker discovers Capital One's WAF (ModSecurity on EC2) has
        an SSRF-exploitable configuration.
        Chain node: [external attacker]
        Permission: none required

STEP 1. Attacker sends crafted HTTP request through WAF to internal URL:
                http://169.254.169.254/latest/meta-data/iam/security-credentials/
        Chain node: [WAF EC2 instance] — role attached: *WAF-Role
        Permission granted (to instance): sts:AssumeRole (implicit, IMDSv1)
        This corresponds to PathTriage attack path P2 (IMDS SSRF).

STEP 2. IMDSv1 responds with the WAF-Role's temporary credentials
        (AccessKey, SecretKey, SessionToken). No token requirement.
        Chain node: [attacker now holds WAF-Role temp credentials]
        Permission granted (as WAF-Role): scoped to S3

STEP 3. Attacker exercises WAF-Role permissions off-box from her own
        infrastructure. AWS treats the calls as legitimate WAF activity.
        Chain node: [attacker impersonating WAF-Role]
        Correspondence: PathTriage attack path P6 (Instance Profile Abuse)

STEP 4. Attacker enumerates over 700 accessible S3 buckets, then reads
        objects — ~30 GB of structured/semi-structured customer data.
        Chain node: [S3 buckets containing 106M customer records]
        Permission exercised: s3:ListBucket, s3:GetObject
```

### Sources

- **U.S. v. Paige A. Thompson**, W.D. Wash., Case No. 19-mj-00344 (filed 2019-07-29).
  Federal indictment. First-party source for attack timeline and technique.
- Capital One Financial Corporation, Form 8-K filed with SEC, 2019-07-29.
  Regulatory disclosure. First-party source for scope of impact.
- Novaes Neto, N. et al. (2022). "A Systematic Analysis of the Capital
  One Data Breach: Critical Lessons Learned." *ACM Transactions on
  Privacy and Security*, 25(4), Article 30. https://dl.acm.org/doi/full/10.1145/3546068
  Peer-reviewed academic analysis. Preferred citation for the report.
- Krebs, B. (2019, August 2). "What We Can Learn From the Capital One Hack."
  https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/
- AWS. (2019, November). "Instance Metadata Service Version 2 (IMDSv2)."
  AWS Documentation. AWS's public response to the class of attack.

### Why this case matters for PathTriage motivation

**Chain-level analysis was needed but absent.** Every individual permission
in the chain was legitimate. Static IAM analysis (Cloudsplaining, IAM
Access Analyzer) would have flagged the WAF-Role's S3 read as
"broad-scope" but not as "exploitable via SSRF path". Runtime detection
(GuardDuty at the time) would have seen the credential use but not
correlated it to abnormal source location.

**The four-month detection lag is the operational cost.** Between attack
and detection, over 700 buckets were enumerated and 30 GB exfiltrated.
Ranking would have surfaced the WAF-Role-to-S3 path as high-risk
*before* the SSRF vulnerability was found, changing it from
"missing-control" into "known priority path".

**Report angle**: This is the case that established cloud misconfiguration
as the dominant breach vector for cloud-first organizations. Use it as
the opening scene-setter for Chapter 1.

---

## Case 2 — Snowflake 2024 (Multi-tenant SaaS)

### Executive summary (2 sentences for opening)

Between April and June 2024, a financially motivated threat actor tracked
by Mandiant as UNC5537 used credentials — mostly stolen years earlier by
infostealer malware — to log into approximately 165 Snowflake customer
tenants that had not enforced multi-factor authentication. Victims
included Ticketmaster, AT&T, Santander, Advance Auto Parts, and Neiman
Marcus; AT&T alone had records of nearly all its cellular customers
exposed (73 million subjects) and reportedly paid $370,000 in extortion
to have data deleted.

### Timeline

| Date | Event | Source |
|---|---|---|
| Nov 2020 – 2024 | Infostealer malware harvests Snowflake credentials from user endpoints (Lumma, MetaStealer, Raccoon, RedLine, RisePro, Vidar) | Mandiant June 2024 report |
| 2024-04-14 | UNC5537 active exfiltration campaign begins | Mandiant |
| 2024-04 | AT&T customer data compromised (73M subjects) | AT&T SEC filing |
| 2024-05-23 | Snowflake becomes aware of unauthorised access | Snowflake CISO blog |
| 2024-05-30 | Snowflake, Mandiant, CrowdStrike coordinated public disclosure | Snowflake blog |
| 2024-06-10 | Mandiant publishes UNC5537 threat intel report | Google Cloud blog |
| 2024-10-30 | Alexander "Connor" Moucka (aka "Judische") arrested in Canada | DOJ |
| 2024-11 | US DOJ unseals federal indictment vs Moucka and Binns | DOJ |

Detection lag: **weeks to months** per tenant (individual tenant
detection times not disclosed as a single figure).

### IAM chain reconstruction

Snowflake's own platform was **not** compromised — the failure was in
customer identity architecture. The chain is unusually short but exposes
a systemic Identity-and-Access-Management design flaw at the platform
level:

```
STEP 0. Infostealer malware (e.g. Lumma) infects an endpoint used by a
        Snowflake customer employee — often personal / contractor devices
        used for both work and personal browsing. Credentials for
        multiple SaaS services are exfiltrated to a criminal marketplace.
        Chain node: [end-user's cached Snowflake credentials]
        Contributing condition: BYOD / mixed-use devices

STEP 1. UNC5537 purchases the credentials (or obtains them from earlier
        breaches) and logs into the customer's Snowflake tenant via
        standard authentication. NO MFA challenge is issued because MFA
        was optional per Snowflake's platform defaults.
        Chain node: [attacker holds valid customer login]
        Design condition: MFA opt-in, not opt-out at platform default

STEP 2. No network allowlist is configured on the customer tenant, so
        Mullvad/PIA VPN egress IPs (attacker infrastructure) are
        accepted. ~80% of victim tenants had no network allow lists.
        Chain node: [attacker session inside customer data warehouse]
        Design condition: allow-any-network default

STEP 3. Attacker deploys custom recon utility "FROSTBITE" (Mandiant
        naming). Enumerates tables, views, warehouses.
        Chain node: [full read access to customer's data warehouse]

STEP 4. Data exfiltration via Snowflake's own storage/query APIs
        (COPY INTO ... TO STAGE). This uses the platform's normal data
        movement path, bypassing external network egress detection.
        Chain node: [attacker's staging area]

STEP 5. Data listed for sale on cybercrime forums. Extortion demands
        issued to affected organisations. AT&T reportedly paid $370K.
```

### Sources

- Mandiant / Google Cloud (2024, June 10). "UNC5537 Targets Snowflake
  Customer Instances for Data Theft and Extortion." Threat Intelligence
  blog. https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion
  **First-party threat intelligence — preferred citation.**
- Snowflake Inc. (2024, May 30). "Detecting and Preventing Unauthorized
  User Access." Snowflake blog. Snowflake's own public disclosure.
- AT&T Inc. Form 8-K filed with SEC, 2024-07-12. Confirmation of 73M
  customer records exposed.
- U.S. v. Connor Moucka and John Binns, D. Mass., federal indictment
  unsealed November 2024. First-party legal source.
- Krebs, B. (2024, June 21). "Snowflake Breach Snares Ticketmaster,
  Santander Bank." https://krebsonsecurity.com/2024/06/

### Why this case matters for PathTriage motivation

**Optional-MFA is a platform-level IAM design decision.** Snowflake had
not made MFA mandatory. The 165+ affected customers each independently
inherited that default. In SaaS-multi-tenant contexts, chain analysis
must include the platform's identity architecture as a node — a
consideration existing tools (which analyse individual tenant configs
only) fundamentally cannot express.

**Credentials-only breaches without vulnerability exploitation are now
the dominant category.** Verizon DBIR 2024 reports stolen credentials as
initial vector for 24% of all breaches (see `chapter1_statistics.md`).
Path-based analysis extends beyond permission graphs to include
credential surface — where credentials live outside the platform (in
infostealer logs, browser caches, secrets managers).

**Report angle**: The AT&T subset (73M subjects, most-of-customer-base
exposure) is a strong data point for the "single misconfigured path can
affect the entire tenant" argument. Use Snowflake as the case for
platform-level identity architecture as a first-class chain concern.

---

## Case 3 — Microsoft Midnight Blizzard 2024 (Multi-cloud / Multi-tenant)

### Executive summary (2 sentences for opening)

In late November 2023, the Russian state-sponsored threat actor tracked
by Microsoft as Midnight Blizzard (NOBELIUM, APT29) compromised a legacy
non-production Entra ID tenant via password spray against an account
without MFA, then abused a legacy OAuth application in that tenant that
held elevated Exchange permissions in Microsoft's production corporate
tenant. Over two months of undetected access, the actor created
additional malicious OAuth applications, granted them
`full_access_as_app` on Office 365 Exchange, and exfiltrated emails from
senior leadership, cybersecurity, and legal staff before Microsoft
detected the intrusion on 2024-01-12.

### Timeline

| Date | Event | Source |
|---|---|---|
| Late Nov 2023 | Password spray against legacy test tenant succeeds against non-MFA account | Microsoft MSRC 2024-01-19 |
| Nov–Dec 2023 | Actor creates malicious OAuth apps in test tenant | Microsoft MSRC 2024-01-25 |
| Dec 2023 | Actor abuses legacy OAuth app with elevated Exchange permissions to pivot into corporate tenant | Microsoft MSRC 2024-01-19 |
| Dec 2023 – 2024-01-12 | Email exfiltration from Microsoft senior leadership, cybersec, legal | Microsoft MSRC 2024-01-19 |
| 2024-01-12 | Microsoft detects and begins eviction | Microsoft MSRC 2024-01-19 |
| 2024-01-17 | Microsoft files SEC 8-K | SEC filing |
| 2024-01-19 | Microsoft first public MSRC blog post | MSRC blog |
| 2024-01-25 | Microsoft second MSRC post — guidance for responders | MSRC blog |
| 2024-03-08 | Microsoft update: source code repos accessed; ongoing password spray against Microsoft customers using secrets extracted from stolen emails; February attack volume 10× January | MSRC blog |
| 2024-04 | CISA Emergency Directive 24-02 orders US federal agencies to reset any Microsoft-shared credentials | CISA |

Detection lag: **approximately 7 weeks** from initial compromise to Microsoft detection.

### IAM chain reconstruction

The chain is the case study most directly aligned with PathTriage's
convergence primitives — every step maps to a defender-observable event:

```
STEP 0. Legacy non-production tenant exists with a legacy OAuth app that
        had been granted elevated permissions to the Microsoft corporate
        tenant. This trust configuration is the pre-existing
        misconfiguration.
        Chain node: [legacy test tenant] --trusts--> [legacy OAuth app] --scope--> [corporate tenant]
        Design condition: cross-tenant OAuth application scope with
                          elevated Exchange permissions retained after
                          intended use ended

STEP 1. Password spray attack targets Entra ID user accounts in the
        legacy tenant. A non-MFA account is compromised.
        Chain node: [attacker holds legacy tenant user credentials]
        Correspondence: precursor to PathTriage attack path Z1 (Azure
                        Entra ID credential compromise)

STEP 2. Attacker uses the compromised account to create a new user with
        elevated privileges within the legacy tenant. New user consents
        to actor-created malicious OAuth applications.
        Chain node: [malicious OAuth apps registered in legacy tenant]
        Correspondence: PathTriage attack path Z3 (roleAssignments-write)

STEP 3. Actor's malicious OAuth apps are assigned service principals in
        the corporate tenant via the cross-tenant trust of Step 0.
        The apps are assigned the "full_access_as_app" role on Exchange
        Web Services (EWS).
        Chain node: [service principals in Microsoft corporate tenant
                     with full_access_as_app on Exchange]
        Correspondence: PathTriage attack path Z7 (Trust topology)

STEP 4. Using OAuth application-only permissions (no user context),
        actor calls EWS to enumerate and download mailboxes belonging
        to Microsoft senior leadership, cybersecurity, and legal staff.
        Chain node: [exfiltrated email contents]
        Detection difficulty: OAuth application-only calls blend with
                              legitimate service traffic; residential
                              proxies mask attacker IP.

STEP 5. Actor extracts secrets from stolen emails and re-uses them to
        password-spray Microsoft customers. Volume 10× higher in
        February 2024 than January 2024, per MSRC 2024-03-08 update.
        Chain node: [downstream customer tenants]
```

### Sources

- Microsoft Security Response Center (2024, January 19). "Microsoft
  Actions Following Attack by Nation State Actor Midnight Blizzard."
  https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/
  **First-party first disclosure — preferred citation for initial timeline.**
- Microsoft Threat Intelligence (2024, January 25). "Midnight Blizzard:
  Guidance for responders on nation-state attack."
  https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
  **First-party technical detail — preferred citation for attack chain.**
- Microsoft Security Response Center (2024, March 8). Update: source
  code access, downstream customer targeting.
- Microsoft Corporation, Form 8-K filed with SEC, 2024-01-17.
- Wiz Research (2024, February 8). "Midnight Blizzard breach: analysis
  and best practices." https://www.wiz.io/blog/midnight-blizzard-microsoft-breach-analysis-and-best-practices
  Independent technical analysis with OAuth chain reconstruction.
- CISA Emergency Directive 24-02 (2024, April 2). US federal response.

### Why this case matters for PathTriage motivation

**Every step in the chain is defender-observable, but no single event
looks anomalous.** Password spray fails until it succeeds; OAuth app
registration is legitimate administrative activity; role assignment
happens routinely. The signal is the *composition*: a fresh OAuth app
that gets `full_access_as_app` on Exchange from a newly-created user
account in a tenant that has cross-tenant scope into production. This is
exactly what PathTriage primitive 05 (trust topology) is designed to
detect, and the D-Z7-02 finding (Azure OBO structurally blocks
SP-to-SP chain) is directly relevant.

**Cross-tenant OAuth trust is the multi-cloud identity blast radius
problem.** Legacy test tenants that retain permissions into production
are the SaaS equivalent of long-forgotten AWS cross-account trust roles.
Path-level analysis extended to include cross-tenant OAuth application
scope is what PathTriage's convergence primitive 05 formalises.

**Detection took 7 weeks despite Microsoft's own security tooling.** The
attack targeted Microsoft, a vendor with world-class detection
infrastructure — and still succeeded for 7 weeks. This underscores that
the problem is not detection *maturity* but detection *methodology*: the
individual events were logged, but no rule joined them.

**Report angle**: This is the most directly-mapped case to PathTriage's
Azure primitives. Reference the connection to Z3, Z7, and the D-Z7-02
finding explicitly. Use it as the case for cross-cloud / cross-tenant
chain concerns being distinct from single-account chain concerns.

---

## Cross-case observations (for Chapter 1 §1.1.2)

Three patterns emerge that motivate PathTriage's approach:

1. **Chain composition, not individual permission.** In all three cases,
   every individual permission was legitimate for its principal. The
   breach was possible only because the chain composed into
   catastrophic capability. Static permission audits (Cloudsplaining,
   IAM Access Analyzer) do not model chains. Runtime SIEM rules (Sigma,
   Datadog) fire on individual events but do not join them into chains.

2. **Detection lag is measured in weeks-to-months, not seconds.** Capital
   One: 4 months. Midnight Blizzard: 7 weeks. Snowflake per-tenant:
   weeks. The operational cost of undetected chains is data loss, not
   just risk exposure. Ranking chains before compromise reduces exposure
   window by turning "unknown priority" into "known priority to
   remediate".

3. **Chain analysis must include the identity architecture, not just
   permissions.** Snowflake's optional-MFA policy is not a "permission"
   in any IAM graph. Midnight Blizzard's cross-tenant OAuth scope is not
   captured by single-tenant analysis. Capital One's IMDSv1 default is
   not an IAM policy at all. Each case required including
   platform-level identity design as a first-class chain concern.

These three observations are the argumentative through-line from case
studies (§1.1) into gap analysis (§1.2). They should recur in §1.4 as
motivations for PathTriage's four contributions.
