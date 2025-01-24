# Web Application Security Scanner

A Python-based tool to scan web applications for vulnerabilities such as SQL Injection, XSS, CSRF, and more. This project includes features for anomaly detection, real-time traffic monitoring, and generating comprehensive vulnerability reports.

---

## 🚀 Features
- Real-time traffic monitoring and visualization.
- Anomaly detection using machine learning (Isolation Forest).
- Vulnerability scans for:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Cross-Site Request Forgery (CSRF)
  - Open Redirect
  - Command Injection
  - File Upload Vulnerabilities
  - HTTP Response Splitting
  - Path Traversal
  - Clickjacking
  - Directory Listing
- OWASP ZAP integration for additional vulnerability checks.
- Automatic PDF report generation summarizing findings.

---

## 📋 Prerequisites
- **Python 3.8+**
- Recommended: A virtual environment for dependencies.

---

## 🔧 Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/username/repository-name.git
   cd repository-name
Install dependencies:
pip install -r requirements.txt
## Run the application:
python major.py
🛠️ Usage
1. Start Scanning
Enter the target URL in the GUI and click the desired scan button (e.g., SQL Injection, XSS).
2. Real-Time Monitoring
Use the Live Traffic Monitor option to monitor response times.
Detect anomalies using the Anomaly Detection feature.
3. Generate Report
After scanning, click Generate Report PDF to create a detailed summary of vulnerabilities.
## 📚 Technology Stack
Frontend: CustomTkinter for GUI
Backend: Python libraries for processing and analysis
Machine Learning: Isolation Forest (from scikit-learn)
Visualization: Matplotlib
PDF Generation: FPDF
Web Requests: Requests library
## 🙌 Contributors
Siddharth Gupta
Rohini M Gowda
Teja S
Manasa M
