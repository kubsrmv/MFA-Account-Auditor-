import streamlit as st
import pandas as pd
from dateutil import parser
from datetime import datetime, timezone
import os

# OpenAI import (safe if not installed)
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # we'll handle gracefully later

st.set_page_config(page_title="MFA & Account Hygiene Auditor", layout="wide")

STALENESS_DAYS = 90
RECENT_DAYS = 14

st.title("MFA & Account Hygiene Auditor")
st.write(
    "Upload a CSV export of users to assess MFA coverage, stale accounts, and risky admins. "
    "Columns expected (case-insensitive): email, department, role, mfa_enabled, last_login, status, admin"
)

uploaded = st.file_uploader("Upload users CSV", type=["csv"])

def to_bool(x):
    if pd.isna(x):
        return False
    s = str(x).strip().lower()
    return s in {"true", "yes", "1", "y", "t"}

def parse_ts(x):
    if pd.isna(x) or str(x).strip() == "":
        return None
    try:
        return parser.parse(str(x)).astimezone(timezone.utc)
    except Exception:
        return None

# ---- safe secrets helper (env first, then st.secrets; never crash) ----
def get_secret(name: str, default: str | None = None):
    v = os.getenv(name)
    if v:
        return v
    try:
        return st.secrets[name]
    except Exception:
        return default

if uploaded:
    df = pd.read_csv(uploaded)
    colmap = {c.lower().strip(): c for c in df.columns}

    def g(name):
        return colmap.get(name, None)

    needed = ["email", "mfa_enabled", "last_login", "status", "admin"]
    missing = [n for n in needed if g(n) is None]
    if missing:
        st.error(f"Missing columns: {', '.join(missing)}")
        st.stop()

    now = datetime.now(timezone.utc)

    # Normalize
    df["_email"] = df[g("email")].astype(str).str.strip().str.lower()
    df["_dept"] = df[g("department")].astype(str).str.strip() if g("department") else "General"
    df["_role"] = df[g("role")].astype(str).str.strip() if g("role") else ""
    df["_mfa"] = df[g("mfa_enabled")].apply(to_bool)
    df["_admin"] = df[g("admin")].apply(to_bool)
    df["_status"] = df[g("status")].astype(str).str.strip().str.lower()
    df["_last_login"] = df[g("last_login")].apply(parse_ts)
    df["_days_since_login"] = df["_last_login"].apply(lambda t: (now - t).days if t else None)
    df["_never_logged"] = df["_last_login"].isna()

    # ---- Metrics (use ACTIVE users as the base) ----
    total = len(df)
    active_mask = df["_status"].isin(["active", "enabled", ""])
    active = int(active_mask.sum())

    # MFA coverage among active only
    mfa_cov = 100.0 * (df.loc[active_mask, "_mfa"].sum() / max(1, active))

    # Admins among active only (to match the w/o MFA count)
    admins_active = int(df.loc[active_mask, "_admin"].sum())
    admins_wo_mfa = int((df["_admin"] & ~df["_mfa"] & active_mask).sum())

    stale = int((active_mask & (df["_days_since_login"].fillna(10**6) > STALENESS_DAYS)).sum())
    never_recent = int((active_mask & df["_never_logged"]).sum())
    disabled_recent_login = int((~active_mask & (df["_days_since_login"].fillna(10**6) <= RECENT_DAYS)).sum())

    # Simple risk score (demo)
    risk = 100
    risk -= int(mfa_cov * 0.4)             # MFA coverage helps
    risk -= min(30, admins_wo_mfa * 5)     # punish admin w/o MFA
    risk -= min(20, stale * 1)             # stale accounts add risk
    risk = max(0, min(100, risk))

    # KPI tiles
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Users (active)", f"{active}/{total}")
    m2.metric("MFA coverage", f"{mfa_cov:.1f}%")
    m3.metric("Admins (active) w/o MFA", str(admins_wo_mfa))
    m4.metric("Risk score (lower is better)", str(risk))

    # Findings
    st.subheader("Findings (prioritized)")
    f_admin_nomfa = df[(df["_admin"]) & (~df["_mfa"]) & active_mask]
    f_stale = df[active_mask & (df["_days_since_login"].fillna(10**6) > STALENESS_DAYS)]
    f_never = df[active_mask & df["_never_logged"]]
    f_disabled_recent = df[(~active_mask) & (df["_days_since_login"].fillna(10**6) <= RECENT_DAYS)]

    st.write("**1) Admins without MFA (fix immediately)**")
    st.dataframe(
        f_admin_nomfa[["_email", "_dept", "_role"]].rename(columns={"_email": "email", "_dept": "department", "_role": "role"}),
        use_container_width=True,
    )

    st.write(f"**2) Stale active accounts > {STALENESS_DAYS} days**")
    st.dataframe(
        f_stale[["_email", "_dept", "_role", "_days_since_login"]].rename(
            columns={"_email": "email", "_dept": "department", "_role": "role", "_days_since_login": "days_since_login"}
        ),
        use_container_width=True,
    )

    st.write("**3) Active accounts that never logged in**")
    st.dataframe(
        f_never[["_email", "_dept", "_role"]].rename(columns={"_email": "email", "_dept": "department", "_role": "role"}),
        use_container_width=True,
    )

    st.write(f"**4) Disabled/suspended but logged in within last {RECENT_DAYS} days (review)**")
    st.dataframe(
        f_disabled_recent[["_email", "_dept", "_role", "_days_since_login", "_status"]].rename(
            columns={"_email": "email", "_dept": "department", "_role": "role", "_days_since_login": "days_since_login", "_status": "status"}
        ),
        use_container_width=True,
    )

    # Chart
    st.subheader("MFA coverage by department")
    dept = (
        df.loc[active_mask]
        .groupby("_dept")["_mfa"]
        .mean()
        .mul(100)
        .sort_values(ascending=False)
    )
    st.bar_chart(dept)

    # ----------------------------
    # 🧠 Chat assistant (gpt-5 → gpt-4o fallback), secrets safe
    # ----------------------------
    OPENAI_API_KEY = get_secret("OPENAI_API_KEY")
    PRIMARY_MODEL = (get_secret("OPENAI_MODEL") or "gpt-5").strip()
    FALLBACK_MODEL = "gpt-4o"

    client = OpenAI(api_key=OPENAI_API_KEY) if (OPENAI_API_KEY and OpenAI) else None

    def chat_call(messages, temperature=0.2):
        if not client:
            raise RuntimeError("No OpenAI client. Add OPENAI_API_KEY via .streamlit/secrets.toml or env var.")
        try:
            return client.chat.completions.create(
                model=PRIMARY_MODEL,
                temperature=temperature,
                messages=messages,
            )
        except Exception as e:
            msg = str(e).lower()
            if any(x in msg for x in ("model", "unsupported", "not found", "does not exist", "unknown")):
                return client.chat.completions.create(
                    model=FALLBACK_MODEL,
                    temperature=temperature,
                    messages=messages,
                )
            raise

    def assistant_reply(user_msg: str) -> str:
        if not client:
            return "⚠️ OpenAI client not available. Configure OPENAI_API_KEY in .streamlit/secrets.toml or as an env var."
        try:
            kpi_context = (
                f"Active users: {active}/{total}\n"
                f"MFA coverage: {mfa_cov:.1f}%\n"
                f"Admins (active) without MFA: {admins_wo_mfa}\n"
                f"Stale active accounts (> {STALENESS_DAYS} days): {stale}\n"
                f"Active never-logged-in: {never_recent}\n"
                f"Disabled with login <= {RECENT_DAYS} days: {disabled_recent_login}\n"
            )
            sample_admins = f_admin_nomfa["_email"].head(3).tolist()
            sample_line = (
                f"Example admin emails without MFA (first 3): {', '.join(sample_admins)}"
                if sample_admins else "No admin emails without MFA."
            )
            system = (
                "You are a concise cybersecurity analyst embedded in a Streamlit dashboard for identity risk. "
                "Use the provided KPIs to explain findings, prioritize fixes, and generate short executive summaries. "
                "Default to counts/metrics; only reveal email addresses if the user explicitly asks."
            )
            resp = chat_call(
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": f"Current KPIs:\n{kpi_context}\n{sample_line}\n\nUser question: {user_msg}"},
                ],
                temperature=0.2,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            return f"⚠️ Chat error: {e}\n\nCheck OPENAI_API_KEY/OPENAI_MODEL in Secrets or env."

    with st.sidebar:
        st.header("🧠 Security Assistant")
        if "chat" not in st.session_state:
            st.session_state.chat = []
        for m in st.session_state.chat:
            with st.chat_message(m["role"]):
                st.markdown(m["content"])
        prompt = st.chat_input("Ask about this report… e.g., 'summarize risks' or 'what do I fix first?'")
        if prompt:
            st.session_state.chat.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)
            with st.chat_message("assistant"):
                reply = assistant_reply(prompt)
                st.markdown(reply)
            st.session_state.chat.append({"role": "assistant", "content": reply})

    # Downloadable report (ASCII only)
    lines = []
    lines.append("# MFA & Account Hygiene Report\n")
    lines.append(f"- **Generated:** {now.strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"- **Users (active/total):** {active}/{total}")
    lines.append(f"- **MFA coverage:** {mfa_cov:.1f}%")
    lines.append(f"- **Admins (active / w/o MFA):** {admins_active} / {admins_wo_mfa}")
    lines.append(f"- **Stale active accounts > {STALENESS_DAYS} days:** {stale}")
    lines.append(f"- **Active never-logged-in accounts:** {never_recent}")
    lines.append(f"- **Disabled but logged in <= {RECENT_DAYS} days:** {disabled_recent_login}\n")
    lines.append("## Top Remediations")
    if len(f_admin_nomfa):
        lines.append(f"- Enforce MFA for **{len(f_admin_nomfa)} admin(s)** immediately.")
    if stale:
        lines.append(f"- Review/disable **{stale} stale active account(s)** (> {STALENESS_DAYS} days).")
    if never_recent:
        lines.append(f"- Remove or onboard **{never_recent} never-logged-in active account(s)**.")
    if disabled_recent_login:
        lines.append(f"- Investigate **{disabled_recent_login} disabled account(s)** with recent logins.")
    lines.append("\n## Admins without MFA")
    for e in f_admin_nomfa["_email"].tolist():
        lines.append(f"- {e}")
    report_md = "\n".join(lines)

    st.download_button("Download Markdown report", report_md, file_name="mfa_account_hygiene_report.md")

else:
    # Minimal sidebar even without data
    with st.sidebar:
        st.header("🧠 Security Assistant")
        st.info("Upload a CSV to enable the assistant and KPIs.")
        st.caption("Expected headers: email, department, role, mfa_enabled, last_login, status, admin")

    st.info("Tip: Create a CSV with headers: email,department,role,mfa_enabled,last_login,status,admin")
    st.code(
        """email,department,role,mfa_enabled,last_login,status,admin
alice@acme.com,Finance,Analyst,true,2025-08-10,active,false
bob@acme.com,IT,SysAdmin,false,2025-07-01,active,true
carol@acme.com,Sales,Manager,true,2025-04-12,active,false
dave@acme.com,Marketing,Intern,false,,active,false
eve@acme.com,IT,Engineer,true,2025-08-12,disabled,false
support@acme.com,Support,Shared,false,2025-05-01,active,false
""",
        language="csv",
    )
