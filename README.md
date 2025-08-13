# MFA & Account Hygiene Auditor

A lightweight **Streamlit** app for businesses to spot identity risks from a simple **users CSV**. It computes KPIs, flags risky accounts, and includes a built-in **AI assistant** that summarizes findings and suggests remediations.

https://mfa-accounthygieneauditor.streamlit.app/

---

## What it shows
- **MFA coverage** (overall and by department)
- **Admins without MFA** (highest priority)
- **Stale active accounts** (> `STALENESS_DAYS`, default 90)
- **Active accounts that never logged in**
- **Disabled users with recent logins** (≤ `RECENT_DAYS`, default 14)
- **Risk score (0–100)** for a quick posture read
- **Downloadable Markdown report**
- **🧠 Sidebar chat assistant** (uses OpenAI) to explain findings / draft exec summaries

---

## Quick start (local)

1) **Install**
```bash
pip install -r requirements.txt
