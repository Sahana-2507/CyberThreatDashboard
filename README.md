# AEGIS Cyber Threat Detection & SOC Dashboard

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)
![Frontend](https://img.shields.io/badge/Frontend-HTML5%20%7C%20CSS3%20%7C%20JS-brightgreen.svg)
![Status](https://img.shields.io/badge/System-Operational-emerald.svg)

An enterprise-grade **Cyber Threat Detection Dashboard & Security Operations Center (SOC)** built with a multi-threaded Java Heuristic Inspection Engine and a dark SOC monitoring interface.

---

## 🌟 Key Features

* **Real-Time Traffic Simulator & Telemetry**: Background network monitoring thread simulating live packets and detecting intrusions with zero external dependencies.
* **Heuristic Inspection Engine**:
  * **SQL Injection (SQLi)**: Detects boolean authentication bypasses and malicious SQL statements.
  * **Cross-Site Scripting (XSS)**: Identifies reflected and executable script tags in parameters.
  * **Command Injection**: Detects shell separators (`;`, `&&`, `||`) and system execution probes.
  * **Directory / Path Traversal**: Catches `../` sequences and URL-encoded traversal patterns (`%2e%2e`).
  * **Exploit Signatures**: Flags WICAR benign exploit artifacts, ActiveX probes, and SMB exploits.
  * **Phishing Detection**: Identifies brand impersonation and credential harvesting domains.
  * **Reconnaissance Probes**: Classifies network mapping and diagnostic port scans.
* **Interactive Manual Packet & URL Inspector**: Test payloads on-demand with a pre-configured **Load Sample Attack** dropdown (SQLi, XSS, Command Injection, Path Traversal).
* **Severity Filtering**: Live client-side incident filtering (**All**, **Critical**, **High**, **Medium**, **Low**) with real-time incident counters.
* **Data Export**: One-click **Export to CSV** generating clean, RFC 4180-compliant `.csv` audit logs directly from the browser.
* **SOC Aesthetics**: High-contrast dark navy glassmorphism layout, electric cyan accents, Chart.js doughnut analytics, and responsive mobile drawer.

---

## 🚀 Quick Start Guide

### Prerequisites
* Java Development Kit (JDK 17 or higher)
* Any modern web browser

### Running Locally

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Sahana-2507/CyberThreatDashboard.git
   cd CyberThreatDashboard
   ```

2. **Compile the Java Server**:
   ```bash
   javac -d bin src/CyberThreatServer.java
   ```

3. **Start the Threat Detection Engine**:
   ```bash
   java -cp bin CyberThreatServer
   ```

4. **Access the Dashboard**:
   Open [http://localhost:8080](http://localhost:8080) in your browser.

---

## 📁 Project Structure

```
├── src/
│   └── CyberThreatServer.java   # Core HTTP server, Heuristic Analyzer & Traffic Simulator
├── web/
│   ├── index.html               # Enterprise SOC Dashboard structure
│   ├── style.css                # Dark cybersecurity SOC design system
│   └── app.js                   # Telemetry polling, Chart.js, filtering & CSV exporter
├── test_payloads.txt            # Benchmark attack dataset for manual verification
├── .gitignore                   # Ignore bin/, out/, IDE files
└── README.md                    # Project documentation
```

---

## 🧪 Benchmark Payloads

Refer to [`test_payloads.txt`](test_payloads.txt) for a comprehensive list of sample vectors:
* **SQLi**: `GET /users?id=' OR '1'='1' HTTP/1.1`
* **XSS**: `POST /comment?msg=<script>alert(1)</script>`
* **Command Injection**: `POST /api/exec cmd=ping 127.0.0.1; whoami`
* **Directory Traversal**: `GET /files?path=../../etc/passwd HTTP/1.1`
* **Benign Traffic**: `GET /home/profile HTTP/1.1`
