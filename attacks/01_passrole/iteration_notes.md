# Path 1 — 3 Iterations (Cheat Sheet)

> **Theme:** Real attacker bundles + real regional defaults > textbook minimal labs.

| # | What broke | Fix | Why it matters |
|---|---|---|---|
| **1** | Policy missing `ec2:CreateTags` | Added `CreateTags` to attacker policy | Real attacker bundles aren't minimal |
| **2** | Admin + attacker credentials getting mixed up | Made the credential boundary explicit | Verify from the attacker's view only |
| **3** | `t2.micro` no longer Free Tier in Sydney | Switched to `t3.micro` | Regional defaults change over time |

---

## If asked more

**Iteration 1** — *"In practice, anyone who has `RunInstances` almost always has `CreateTags` too. So minimal-policy labs aren't realistic. The catalogue should reflect bundles that actually exist."*

**Iteration 2** — *"If admin credentials leak into the test, the exploit looks like it works even when it shouldn't. The test only means something if it runs as the attacker, with nothing more."*

**Iteration 3** — *"AWS Free Tier rules vary by region and change over time. Worth a comment in the shared baseline so future paths don't trip on this."*

---
