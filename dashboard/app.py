import streamlit as st
import requests
import pandas as pd
from datetime import datetime

API_URL = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="IronSIEM Lite SOC Console",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main {
        background-color: #0f172a;
    }
    .block-container {
        padding-top: 1.5rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #111827, #1f2937);
        padding: 18px;
        border-radius: 14px;
        border: 1px solid #334155;
        box-shadow: 0 0 12px rgba(0,0,0,0.35);
    }
    .metric-title {
        color: #94a3b8;
        font-size: 14px;
    }
    .metric-value {
        color: #f8fafc;
        font-size: 32px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


def fetch_data(endpoint):
    try:
        response = requests.get(f"{API_URL}/{endpoint}", timeout=5)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"Backend nicht erreichbar: {e}")
        return []


events = fetch_data("events")
alerts = fetch_data("alerts")

events_df = pd.DataFrame(events)
alerts_df = pd.DataFrame(alerts)

st.sidebar.title("🛡️ IronSIEM Lite")
page = st.sidebar.radio(
    "SOC Navigation",
    [
        "Overview",
        "Security Events",
        "Alerts",
        "Threat IPs",
        "Investigation"
    ]
)

st.sidebar.markdown("---")
if st.sidebar.button("🔄 Refresh"):
    st.rerun()

st.sidebar.markdown("### Backend")
st.sidebar.code(API_URL)


st.title("🛡️ IronSIEM Lite SOC Console")
st.caption("Lightweight SIEM + OSINT Enricher | Sentinel / Splunk / Wazuh inspired")


# 🔥 SENTINEL STYLE OVERVIEW
if page == "Overview":
    st.subheader("🧠 SOC Overview")

    total_events = len(events_df)
    total_alerts = len(alerts_df)
    high_alerts = len(alerts_df[alerts_df["severity"] == "High"]) if not alerts_df.empty else 0

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("### 🚨 Incidents")
        st.metric("Total", total_alerts)
        st.metric("High Severity", high_alerts)

    with col2:
        st.markdown("### 📊 Activity")
        st.metric("Events", total_events)
        st.metric("Active IPs", events_df["source_ip"].nunique() if not events_df.empty else 0)

    with col3:
        st.markdown("### ⚙️ Automation")
        st.metric("Rules Active", 3)
        st.metric("Triggered", total_alerts)

    st.markdown("---")

    colA, colB = st.columns(2)

    with colA:
        st.markdown("### 📊 Events Timeline")
        if not events_df.empty:
            events_df["timestamp"] = pd.to_datetime(events_df["timestamp"])
            timeline = events_df.groupby(events_df["timestamp"].dt.hour).size()
            st.bar_chart(timeline)
        else:
            st.info("Keine Daten")

    with colB:
        st.markdown("### 🚨 Alert Severity Distribution")
        if not alerts_df.empty:
            severity_counts = alerts_df["severity"].value_counts()
            st.bar_chart(severity_counts)
        else:
            st.success("Keine Alerts")

    st.markdown("---")

    colC, colD = st.columns(2)

    with colC:
        st.markdown("### 🌍 Data Sources (simuliert)")
        fake_sources = pd.Series({
            "Windows Logs": 25,
            "Syslog": 12,
            "Firewall": 8,
            "EDR": 5
        })
        st.bar_chart(fake_sources)

    with colD:
        st.markdown("### 🧠 Analytics (Threat Score)")
        if not events_df.empty:
            risk = events_df.groupby("source_ip").size().sum()
            st.metric("Threat Score", risk)
        else:
            st.metric("Threat Score", 0)


elif page == "Security Events":
    st.subheader("📁 Security Event Explorer")

    if events_df.empty:
        st.info("Keine Security Events vorhanden.")
    else:
        col1, col2, col3 = st.columns(3)

        with col1:
            event_filter = st.selectbox("Event ID", ["All"] + sorted(events_df["event_id"].dropna().unique().tolist()))

        with col2:
            ip_filter = st.selectbox("Source IP", ["All"] + sorted(events_df["source_ip"].dropna().unique().tolist()))

        with col3:
            severity_filter = st.selectbox("Severity", ["All"] + sorted(events_df["severity"].dropna().unique().tolist()))

        filtered = events_df.copy()

        if event_filter != "All":
            filtered = filtered[filtered["event_id"] == event_filter]

        if ip_filter != "All":
            filtered = filtered[filtered["source_ip"] == ip_filter]

        if severity_filter != "All":
            filtered = filtered[filtered["severity"] == severity_filter]

        st.dataframe(filtered, use_container_width=True)


elif page == "Alerts":
    st.subheader("🚨 Alert Center")

    if alerts_df.empty:
        st.success("Keine Alerts erkannt.")
    else:
        for _, alert in alerts_df.iterrows():
            severity = alert.get("severity", "Unknown")

            if severity == "High":
                st.error(f"🚨 {alert['title']}\n\nIP: {alert['source_ip']}\n\n{alert['description']}")
            elif severity == "Medium":
                st.warning(f"⚠️ {alert['title']}\n\nIP: {alert['source_ip']}\n\n{alert['description']}")
            else:
                st.info(f"ℹ️ {alert['title']}\n\nIP: {alert['source_ip']}\n\n{alert['description']}")

        st.markdown("---")
        st.dataframe(alerts_df, use_container_width=True)


elif page == "Threat IPs":
    st.subheader("🌍 Threat IP Overview")

    if events_df.empty:
        st.info("Keine IP-Daten vorhanden.")
    else:
        ip_stats = events_df.groupby("source_ip").agg(
            total_events=("id", "count"),
            failed_logins=("event_id", lambda x: (x == "4625").sum()),
            successful_logins=("event_id", lambda x: (x == "4624").sum())
        ).reset_index()

        ip_stats["risk_score"] = (
            ip_stats["failed_logins"] * 15 +
            ip_stats["total_events"] * 2
        )

        ip_stats = ip_stats.sort_values("risk_score", ascending=False)

        st.dataframe(ip_stats, use_container_width=True)

        st.subheader("🔥 Top Risk IPs")
        st.bar_chart(ip_stats.set_index("source_ip")["risk_score"])


elif page == "Investigation":
    st.subheader("🔎 Investigation Console")

    if events_df.empty:
        st.info("Keine Daten zur Analyse vorhanden.")
    else:
        search_ip = st.text_input("Source IP untersuchen")

        if search_ip:
            result = events_df[events_df["source_ip"].astype(str).str.contains(search_ip, na=False)]

            if result.empty:
                st.warning("Keine Events zu dieser IP gefunden.")
            else:
                st.success(f"{len(result)} Events gefunden.")
                st.dataframe(result, use_container_width=True)

                failed = len(result[result["event_id"] == "4625"])
                success = len(result[result["event_id"] == "4624"])

                st.markdown("### Analyse")
                st.write(f"Fehlgeschlagene Logins: **{failed}**")
                st.write(f"Erfolgreiche Logins: **{success}**")

                if failed >= 5:
                    st.error("Verdacht auf Brute-Force-Aktivität.")
                elif failed > 0 and success > 0:
                    st.warning("Möglicher erfolgreicher Login nach Fehlversuchen.")
                else:
                    st.info("Keine kritische Aktivität erkannt.")