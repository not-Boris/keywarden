Keywarden 🔑🛡️

A lightweight, self-hosted (Work-in-progress!) SSH key management and access auditing platform

![Python](https://img.shields.io/badge/python-3.11%2B-blue)  
![FastAPI](https://img.shields.io/badge/FastAPI-0.114%2B-009688?logo=fastapi)  
![Postgres](https://img.shields.io/badge/Postgres-16-336791?logo=postgresql)  
![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker)  
![License](https://img.shields.io/badge/license-MIT-green)  
![Build](https://img.shields.io/github/actions/workflow/status/**yourusername**/keywarden/ci.yml?branch=main&label=build&logo=github)  

Keywarden is a web-based service designed to simplify secure access to Linux servers. It provides a central place to manage SSH keys, enforce access policies, and monitor login activity — making it easier for sysadmins, homelabbers, and small teams to deploy access security without enterprise overhead.

✨ (TBC) Features
	•	User & Key Management – Upload, register, and manage SSH public keys with enforced algorithms and expiry policies.
	•	Access Requests & Approvals – Users can request server access, with administrators able to approve/deny via a web dashboard.
	•	Automated Key Deployment – Lightweight agent synchronises authorized_keys files on target servers in real time.
	•	Access Auditing – Centralised logs of who accessed what, including successful and failed login attempts.
	•	Dashboards & Reports – Visualise login activity and export compliance reports.
	•	Lightweight & Self-hosted – Built with FastAPI, PostgreSQL, and Docker; easy to run in a homelab or small team environment.

🚀 Tech Stack
	•	Backend: FastAPI (Python), SQLAlchemy
	•	Database: PostgreSQL
	•	Frontend: React (planned), Tailwind, served via Nginx
	•	Agent: Python/Go (lightweight daemon for servers)
	•	Deployment: Docker & Docker Compose

📚 Motivation

SSH is the backbone of secure remote administration, but poor key lifecycle management and lack of auditing create major risks. Enterprise tools like Teleport exist, but are often heavy and complex. Keywarden fills the gap by providing a focused, lightweight, and educational tool for secure SSH access control.

🛠️ Getting Started

There are currently no built artefacts for Keywarden as of 22/09/2025.

```bash
# clone the repository
git clone https://git.ntbx.io/boris/keywarden.git
cd keywarden

# start with docker-compose
docker compose up --build
```