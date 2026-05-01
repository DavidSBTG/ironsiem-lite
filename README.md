# 🛡️ IronSIEM Lite

## 📌 Overview
IronSIEM Lite is a lightweight SIEM (Security Information and Event Management) system with integrated OSINT enrichment.

Built as a hands-on SOC Analyst project to simulate real-world security monitoring.

---

## ⚙️ Features

- 📥 Log Ingestion (FastAPI backend)
- 🧠 Detection Engine (Brute Force detection)
- 🚨 Alerting System
- 🌍 OSINT Enrichment (IP classification)
- 📊 SOC Dashboard (Streamlit UI)
- 🔎 Investigation Console

---

## 🏗️ Architecture

Backend:
- FastAPI
- SQLite
- Detection Engine

Frontend:
- Streamlit Dashboard

---

## 🚀 Run the Project

### Backend

```bash
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
