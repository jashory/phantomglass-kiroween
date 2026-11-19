---
inclusion: manual
---

# Kiroween 2026 Submission & Release Gate Checklist

Run this manual steering audit before locking the Devpost submission:

1. Verify `.kiro/` is tracked in git and NOT listed in `.gitignore`.
2. Verify all 3 core spec artifacts (`requirements.md`, `design.md`, `tasks.md`) exist under `.kiro/specs/phantomglass-core/` and `.kiro/specs/binary-exorcist-engine/`.
3. Verify `.kiro/hooks/*.json` and `.kiro/settings/mcp.json` parse as valid JSON.
4. Verify GitHub Actions Cloud CI passes 100% of automated forensic engine tests and deploys the live HTTPS URL cleanly.
5. Verify Desktop (`1440x900`) and Mobile (`390x844`) viewports have zero overflow, zero console errors, and working 1-click judge specimens.
6. Confirm zero `fetch()` / network exfiltration occurs during photo inspection, manifest audit, and text redaction via browser DevTools Network tab.
