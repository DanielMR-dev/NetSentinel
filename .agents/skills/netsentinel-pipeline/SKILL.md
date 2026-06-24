---
name: netsentinel-pipeline
description: Use for NetSentinel feature work that should run Planner -> Developer -> Reviewer subagents.
---

When invoked, spawn:

1. planner for architecture
2. developer for implementation
3. reviewer for audit

Wait for each phase before moving to the next.
Fix CRITICAL/HIGH reviewer findings before final response.
