# Network Intrusion Detection System (NIDS)

A web-based Network Intrusion Detection System designed to monitor network activity, identify suspicious behaviour, generate security alerts, and provide a centralized dashboard for security monitoring.

## Overview

The Network Intrusion Detection System (NIDS) is a Flask-based cybersecurity project that demonstrates how suspicious network activities and common attack patterns can be identified through rule-based detection.

It provides an interactive dashboard where users can monitor security alerts, view traffic statistics, manage detection rules, and examine blocked IP addresses.

The current implementation uses simulated network traffic to demonstrate detection and monitoring functionality. It is intended for educational and demonstration purposes.

## Features

- **Security Dashboard:** Displays security statistics, attack distribution, traffic trends, and recent alerts.
- **Intrusion Detection:** Demonstrates detection of common attack patterns.
- **Attack Simulation:** Supports simulated Port Scanning, DDoS, Brute Force, SQL Injection, and XSS scenarios.
- **Alert Management:** Displays detected events with severity levels such as Critical, High, Medium, and Low.
- **IP Blocking Management:** Maintains a simulated blocked IP address list.
- **Detection Rules:** Allows administrators to enable or disable detection rules.
- **Traffic Visualization:** Displays traffic statistics using interactive charts.
- **Security Reports:** Provides report generation and CSV export functionality.
- **User Authentication:** Supports login and role-based access.
- **User Profile:** Displays account information, role, department, and access details.
- **Settings Management:** Allows users to configure dashboard refresh intervals and notification preferences.
- **Email Testing:** Includes an SMTP test-email feature when email settings are configured.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| Flask | Web application framework |
| SQLite | Database |
| HTML5 | Dashboard structure |
| CSS3 | Dashboard styling |
| JavaScript | Frontend functionality |
| Chart.js | Data visualization |

## Project Structure

```text
nids/
│
├── app.py
├── nids.db
│
├── templates/
│   ├── dashboard.html
│   ├── login.html
│   └── report.html
│
├── README.md
│
└── requirements.txt
```

The database file is created or initialized by the application when required. Your actual project may contain additional files.

## Installation and Setup

### 1. Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

Navigate into the project folder:

```bash
cd nids
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

### 3. Activate the Virtual Environment

For Windows:

```cmd
venv\Scripts\activate
```

### 4. Install Dependencies

If the project contains a `requirements.txt` file:

```bash
pip install -r requirements.txt
```

Otherwise, install Flask:

```bash
pip install Flask
```

If your application uses additional third-party Python packages, install those as well.

### 5. Run the Application

```bash
python app.py
```

### 6. Open the Dashboard

Open your browser and visit:

```text
http://127.0.0.1:5000
```

## Demo Login Credentials

The application includes demonstration accounts:

| Role | Username | Password |
|---|---|---|
| Administrator | admin | admin123 |
| Analyst | analyst | analyst123 |

**Note:** These are demonstration credentials. Change them and use secure password handling before any production deployment.

## Attack Scenarios

The application provides simulated attack scenarios to demonstrate the detection and alert-generation workflow.

| Attack Type | Description |
|---|---|
| Port Scanning | Demonstrates suspicious port scanning activity |
| DDoS | Simulates a high-volume traffic attack |
| Brute Force | Demonstrates repeated login attempts |
| SQL Injection | Demonstrates SQL injection patterns |
| Cross-Site Scripting (XSS) | Demonstrates suspicious script injection patterns |

## Dashboard Modules

1. **Dashboard:** Overview of network activity and security statistics.
2. **Alerts:** View detected suspicious activities and their severity.
3. **Traffic Monitor:** Visualize simulated traffic and trigger test scenarios.
4. **Reports:** Generate and export security reports.
5. **Blocked IPs:** View and manage the simulated IP blocklist.
6. **Detection Rules:** Configure available detection rules.
7. **My Profile:** View account and role information.
8. **Settings:** Configure dashboard preferences and notification options.

## Security and Limitations

- The current project uses simulated traffic for demonstration and testing.
- The simulated blocklist does not automatically block real network connections.
- The project is not a replacement for a production-grade IDS or firewall.
- SMTP credentials should be stored securely using environment variables.
- The Flask development server should not be used as a production deployment server.

## Future Enhancements

- Real-time packet capture and network traffic analysis.
- Integration with tools such as Scapy.
- Machine-learning-based anomaly detection.
- Advanced threat intelligence integration.
- IP geolocation and attacker visualization.
- Improved authentication and audit logging.
- Deployment on a cloud platform.

## Author

**Sinchana T R**

Computer Science and Engineering (Cyber Security)

GitHub: https://github.com/codewithsinchana

---
*Developed as a cybersecurity project to demonstrate network monitoring, intrusion detection concepts, and security event visualization.*

# NIDS Dashboard (Flask, software-only)
1. `pip install -r requirements.txt`
2. `python app.py` then open http://127.0.0.1:5000  (login: admin / admin123)
Optional email alerts (PowerShell): `$env:SENDER_EMAIL="you@gmail.com"; $env:SENDER_PASSWORD="app-password"; $env:ALERT_RECEIVER="you@gmail.com"`
