---
name: netsentinel-pipeline
description: Use for NetSentinel feature work or bug fixes that must run Plan -> Developer -> Reviewer.
---

# NetSentinel Pipeline

Use only the tokens necessary. Give each subagent a narrow prompt and require it to load Backend Standards and Frontend Standards.

Flow:
1. Plan (You): Create a comprehensive blueprint with exact files, contracts, async/UI design, and acceptance criteria.
2. Developer: implement only the approved scope; run `cargo fmt` and relevant checks/tests.
3. Reviewer: audit diff for CRITICAL/HIGH issues, safety, UI blocking, locks, resources, theme, subscriptions.
4. If Reviewer reports CRITICAL/HIGH, send only those issues back to Developer and repeat review.
5. Final response: minimal summary, files changed, checks, reviewer approval.
