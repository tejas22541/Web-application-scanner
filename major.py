import requests
import json
import customtkinter as ctk
from tkinter import messagebox
from fpdf import FPDF
from PIL import Image, ImageTk
from PIL import ImageEnhance
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from threading import Thread
import time
from matplotlib.animation import FuncAnimation
from sklearn.ensemble import IsolationForest
import numpy as np
from queue import Queue

data_queue = Queue(maxsize=100)

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1)

    def train(self, data):
        reshaped_data = np.array(data).reshape(-1, 1)
        self.model.fit(reshaped_data)

    def detect(self, new_data):
        reshaped_data = np.array(new_data).reshape(-1, 1)
        predictions = self.model.predict(reshaped_data)
        return ["Normal" if p == 1 else "Anomaly" for p in predictions]

# Collect Real-Time Data
def collect_traffic_data(url):
    while True:
        try:
            # Simulate normal traffic response time
            start_time = time.time()
            response = requests.get(url, timeout=5)
            response_time = time.time() - start_time

        except:
            response_time = -1  # Indicate a failure

        # Add data to the queue
        if data_queue.full():
            data_queue.get()
        data_queue.put(response_time)

        # Faster data collection for quicker demonstration
        time.sleep(1)  # Collect data every 0.2 seconds

# Real-Time Visualization
def show_realtime_visuals(url):
    detector = AnomalyDetector()
    traffic_data = []

    def update(frame):
        nonlocal traffic_data

        if not data_queue.empty():
            new_data = data_queue.get()
            traffic_data.append(new_data)
            if len(traffic_data) > 100:
                traffic_data.pop(0)

            # Train anomaly detector on the first 50 samples
            if len(traffic_data) > 50:
                detector.train(traffic_data[:50])
                results = detector.detect(traffic_data[-50:])
                if "Anomaly" in results[-5:]:
                    plt.title("Anomaly Detected: Potential DDoS Threat", color='red')
                else:
                    plt.title("Traffic Monitoring", color='green')

        ax.clear()
        ax.plot(traffic_data, label="Response Time (s)")
        ax.legend(loc="upper left")
        ax.set_xlabel("Time")
        ax.set_ylabel("Response Time (seconds)")
        ax.set_ylim(bottom=0)

    # Create Matplotlib figure
    fig, ax = plt.subplots()
    ani = FuncAnimation(fig, update, interval=1000)

    plt.show()

class TrafficMonitorPopup(ctk.CTkToplevel):
    def __init__(self, parent, target_url):
        super().__init__(parent)
        self.title("Live Traffic Monitor")
        self.geometry("600x400")
        self.target_url = target_url
        self.label = ctk.CTkLabel(self, text=f"Monitoring Traffic for: {self.target_url}", font=("Arial", 14))
        self.label.pack(pady=10)
        self.figure, self.ax = plt.subplots(figsize=(5, 3))
        self.ax.set_title("Live Traffic Data", fontsize=14)
        self.ax.set_xlabel("Time (s)", fontsize=12)
        self.ax.set_ylabel("Response Time (ms)", fontsize=12)
        self.line, = self.ax.plot([], [], 'r-', label="Response Time")
        self.ax.legend()

        # Embed Figure in Tkinter
        self.canvas = FigureCanvasTkAgg(self.figure, self)
        self.canvas.get_tk_widget().pack(pady=10, fill="both", expand=True)

        # Button to Close
        self.close_button = ctk.CTkButton(self, text="Close", command=self.stop_monitoring, font=("Arial", 12))
        self.close_button.pack(pady=10)

        # Variables for Graph
        self.x_data = []
        self.y_data = []
        self.running = True

        # Start Monitoring Thread
        self.monitor_thread = Thread(target=self.monitor_traffic, daemon=True)
        self.monitor_thread.start()

    def monitor_traffic(self):
        start_time = time.time()
        while self.running:
            try:
                # Get response time for the target URL
                response_time = self.get_response_time(self.target_url)
                if response_time is not None:
                    self.x_data.append(time.time() - start_time)
                    self.y_data.append(response_time)

                    # Update Graph
                    self.line.set_data(self.x_data, self.y_data)
                    self.ax.set_xlim(max(0, self.x_data[-1] - 10), self.x_data[-1] + 1)  # Show last 10 seconds
                    self.ax.set_ylim(0, max(self.y_data) + 50)
                    self.canvas.draw()
            except Exception as e:
                print(f"Error: {e}")

            time.sleep(1)  # Update every second

    def get_response_time(self, url):
        try:
            start_time = time.time()
            response = requests.get(url, timeout=5)  # Fetch URL
            elapsed_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            return round(elapsed_time, 2)
        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            return None

    def stop_monitoring(self):
        self.running = False
        self.destroy()
        
class CustomMessageBox(ctk.CTkToplevel):
    def __init__(self, parent, title="Message", message=""):
        super().__init__(parent)
        self.geometry("400x200")
        self.title(title)
        self.resizable(False, False)
        self.grab_set()  # Makes this the active window

        # Styling and Layout
        self.label = ctk.CTkLabel(self, text=message, font=("Arial", 14), wraplength=350)
        self.label.pack(pady=20)

        self.ok_button = ctk.CTkButton(self, text="OK", command=self.close, font=("Arial", 14))
        self.ok_button.pack(pady=10)
        
    def close(self):
        self.grab_release()  
        self.destroy()
        
class WebAppSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.security_headers = []

    def scan_vulnerabilities(self):
        self.check_sql_injection()
        self.check_xss()
        self.check_csrf()
        self.check_open_redirect()
        self.check_command_injection()
        self.check_file_upload_vulnerabilities()
        self.check_http_response_splitting()
        self.check_path_traversal()
        self.check_clickjacking()
        self.check_directory_listing()

    def check_sql_injection(self):
        payloads = [
            "' OR '1'='1",
            "' OR '1'='2",
            "' UNION SELECT username, password FROM users --",
            "'; DROP TABLE users; --",
            "' OR 'a'='a",
            "' AND 1=2 --",
            "'; --",
            "' UNION SELECT NULL, NULL, NULL, NULL --",
            "' UNION SELECT 1,2,3,4 --",
            "' UNION SELECT column1, column2, column3, column4 FROM table_name --",
            "' UNION SELECT null, username, password, null FROM users --",
            "' AND 1=CONVERT(int, (SELECT @@version)) --",
            "' AND 1=1 UNION SELECT NULL, @@version, NULL, NULL --",
            "' AND 1=1 UNION SELECT null, user(), null, null --",
            "' AND 1=1 UNION SELECT null, database(), null, null --",
            "' AND 1=1 UNION SELECT null, current_user(), null, null --",
            "' OR IF(1=1, SLEEP(10), 0) --",
            "' OR IF(1=1, BENCHMARK(1000000, MD5('a')), 0) --",
            "' OR IF(1=1, WAITFOR DELAY '00:00:10', 0) --",
            "' OR IF(1=1, SELECT pg_sleep(10), 0) --",
            "' AND 1=1 AND SLEEP(5) --",
            "' AND (SELECT IF(1=1, SLEEP(5), 0)) --",
            "' AND 1=1 GROUP BY CONCAT(0x3a, table_name) --",
            "' AND 1=1 HAVING 1=1 --",
            "' AND (SELECT @@version) = 1 --",
            "' AND 1=1; SELECT * FROM information_schema.tables --",
            "' AND 1=1; SELECT * FROM users WHERE username = 'admin' --",
            "' AND 1=1; SELECT table_name FROM information_schema.tables --",
        ]
        for payload in payloads:
            test_url = f"{self.target_url}?id={payload}"
            response = requests.get(test_url)
            if "error" not in response.text.lower():
                self.vulnerabilities.append({
                    "type": "SQL Injection",
                    "url": test_url,
                    "description": "SQL Injection allows attackers to interfere with the queries that an application makes to its database.",
                    "solution": "Sanitize user input and use prepared statements or parameterized queries."
                })
        

    def check_xss(self):
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "'><img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<img src='x' onerror='alert(1)'>",
            "<script>document.write('<img src=\"x\" onerror=\"alert(1)\">');</script>"
        ]
        for payload in xss_payloads:
            test_url = f"{self.target_url}?input={payload}"
            response = requests.get(test_url)
            if payload in response.text:
                self.vulnerabilities.append({
                    "type": "XSS",
                    "url": test_url,
                    "description": "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by others.",
                    "solution": "Validate and sanitize user inputs and output encode data before displaying it in the browser."
                })

    def check_csrf(self):
        csrf_token = 'dummy_token' 
        response = requests.get(f"{self.target_url}/change-password", headers={"X-CSRF-Token": csrf_token})
        if response.status_code != 200:
            self.vulnerabilities.append({
                "type": "CSRF",
                "url": f"{self.target_url}/change-password",
                "description": "Cross-Site Request Forgery (CSRF) forces an end user to execute unwanted actions on a web application in which they're authenticated.",
                "solution": "Implement CSRF tokens and ensure they are validated on the server side."
            })
            
            
    def check_open_redirect(self):
        payloads = [
            "http://evil.com",
            "javascript:alert('Open Redirect')",
            "/evilpage",
        ]
        for payload in payloads:
            test_url = f"{self.target_url}?redirect={payload}"
            response = requests.get(test_url)
            if response.history:
                self.vulnerabilities.append({
                    "type": "Open Redirect",
                    "url": test_url,
                    "description": "Open Redirect allows attackers to redirect users to a malicious website.",
                    "solution": "Validate and sanitize redirect URLs to ensure they point only to trusted destinations."
                })
                

    def check_command_injection(self):
        payloads = [
            "; ls",
            "| ls",
            "&& ls",
            "ls"
        ]
        for payload in payloads:
            test_url = f"{self.target_url}?cmd={payload}"
            response = requests.get(test_url)
            if "root" in response.text.lower() or "bin" in response.text.lower():
                self.vulnerabilities.append({
                    "type": "Command Injection",
                    "url": test_url,
                    "description": "Command Injection allows an attacker to inject system commands that are executed by the server.",
                    "solution": "Sanitize user inputs and avoid using user input directly in system calls."
                })

    def check_file_upload_vulnerabilities(self):
        payloads = [
            "evil_script.php",
            "malicious.jpg",
            "payload.exe"
        ]
        for payload in payloads:
            test_url = f"{self.target_url}/upload?file={payload}"
            response = requests.get(test_url)
            if "success" or "successful" or "uploaded" in response.text.lower():  
                self.vulnerabilities.append({
                    "type": "File Upload Vulnerability",
                    "url": test_url,
                    "description": "File upload vulnerabilities can allow malicious files to be uploaded to the server.",
                    "solution": "Ensure file type validation, use file extension whitelisting, and store uploaded files outside the web root."
                })

    def check_http_response_splitting(self):
        payloads = [
            "\r\nSet-Cookie: evil_cookie=malicious_value",
            "\r\nLocation: http://malicious.com"
        ]
        for payload in payloads:
            test_url = f"{self.target_url}?input={payload}"
            response = requests.get(test_url)
            if response.status_code == 200 and payload in response.text:
                self.vulnerabilities.append({
                    "type": "HTTP Response Splitting",
                    "url": test_url,
                    "description": "HTTP Response Splitting allows attackers to inject headers into the response.",
                    "solution": "Sanitize input and ensure headers are properly handled."
                })

    def check_path_traversal(self):
        payloads = [
            "../etc/passwd",
            "../../../../../etc/passwd"
        ]
        for payload in payloads:
            test_url = f"{self.target_url}?file={payload}"
            response = requests.get(test_url)
            if response.status_code == 200 and "root" in response.text.lower():
                self.vulnerabilities.append({
                    "type": "Path Traversal",
                    "url": test_url,
                    "description": "Path Traversal vulnerabilities allow attackers to access sensitive files on the server.",
                    "solution": "Validate and sanitize user input to prevent access to arbitrary files."
                })

    def check_clickjacking(self):
        headers = requests.head(self.target_url).headers
        if "X-Frame-Options" not in headers or headers["X-Frame-Options"] == "ALLOWALL":
            self.vulnerabilities.append({
                "type": "Clickjacking",
                "url": self.target_url,
                "description": "Clickjacking allows malicious sites to trick users into clicking on invisible or disguised elements.",
                "solution": "Implement the X-Frame-Options header with the value 'DENY' or 'SAMEORIGIN'."
            })

    def run_owasp_zap_scan(self):
        target_urll = self.target_url
        zap_api_url = "http://localhost:8080/JSON/ascan/action/scan/"
        params = {"url": target_urll, "recurse": True, "inScopeOnly": True}
        try:
            response = requests.get(zap_api_url, params=params, timeout=10)
            if response.status_code == 200:
                return "Scan initiated successfully. Check ZAP interface for details."
            else:
                return f"Failed to initiate ZAP scan: {response.text}"
        except Exception as e:
            return f"Error connecting to OWASP ZAP API: {str(e)}"
        
    def monitor_website(url, callback):
        def monitor():
            while True:
                try:
                    response = requests.get(url, timeout=5)
                    status = f"UP - {response.status_code}" if response.status_code == 200 else f"DOWN - {response.status_code}"
                except Exception:
                    status = "DOWN"
                callback(status)
                time.sleep(5)
            Thread(target=monitor, daemon=True).start()   
            
    def check_directory_listing(self):
        test_url = f"{self.target_url}/"
        response = requests.get(test_url)
        if response.status_code == 200 and "Index of" in response.text:
            self.vulnerabilities.append({
                "type": "Directory Listing",
                "url": test_url,
                "description": "Directory listing allows users to view a list of files in a directory.",
                "solution": "Ensure that directory listing is disabled on the web server."
            })
        
    def generate_report(self):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        pdf.cell(200, 10, txt="Web Application Security Scan Report", ln=True, align='C')
        pdf.cell(200, 10, txt=f"Target URL: {self.target_url}", ln=True)

        pdf.cell(200, 10, txt="Vulnerabilities Found:", ln=True)
        for vuln in self.vulnerabilities:
            pdf.cell(200, 10, txt=f"{vuln['type']} found at: {vuln['url']}", ln=True)
            pdf.cell(200, 10, txt=f"Description: {vuln['description']}", ln=True)
            pdf.cell(200, 10, txt=f"Solution: {vuln['solution']}", ln=True)

        report_file = f"report_{self.target_url.replace('http://', '').replace('https://', '').replace('/', '_')}.pdf"
        pdf.output(report_file)
        print(f"Report saved as {report_file}")
        messagebox.showinfo("Report Generated", f"Report has been generated successfully! Saved as {report_file}")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
            
        self.title("Web Application Security Scanner")
        self.geometry("565x670")
        ctk.set_appearance_mode("Dark")
        
        bg_image = Image.open("img.jpg")  
        bg_image = bg_image.resize((565, 670))  
        enhancer = ImageEnhance.Brightness(bg_image)
        bg_image = enhancer.enhance(0.5)
        self.bg_image = ImageTk.PhotoImage(bg_image)

        self.bg_label = ctk.CTkLabel(self, image=self.bg_image, text="")
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.header_label = ctk.CTkLabel(self, text="Vulnerability Scanner", font=("Comic sans ms", 32, "italic", "bold"))
        self.header_label.grid(row=0, column=0, columnspan=2, pady=12)
        self.label = ctk.CTkLabel(self, text="Enter the target URL:", font=("Arial", 14, "italic"))
        self.label.grid(row=1, column=0, pady=10, padx=20)

        self.url_entry = ctk.CTkEntry(self, width=300, font=("Arial", 12))
        self.url_entry.grid(row=1, column=1, pady=10)
        
        self.scan_button = ctk.CTkButton(self, text="Scan All", command=self.start_scan, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="red", border_width=2)
        self.scan_button.grid(row=2, column=0, columnspan=2, pady=15)

        self.footer_label = ctk.CTkLabel(self, text="Powered by CustomTkinter \n Final Year Major Project 2024-25 \n \n Developers:\n Siddharth Gupta \n Rohini M Gowda \n Teja S \n Manasa M", font=("Arial", 12))
        self.footer_label.grid(row=12, column=0, columnspan=2, pady=10)
        
        # Vulnerability specific buttons
        self.sql_button = ctk.CTkButton(self, text="Scan for SQL Injection", command=self.scan_sql, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2)
        self.sql_button.grid(row=3, column=0, padx=10, pady=5)

        self.xss_button = ctk.CTkButton(self, text="Scan for XSS", command=self.scan_xss, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2)
        self.xss_button.grid(row=3, column=1, padx=10, pady=5)

        self.csrf_button = ctk.CTkButton(self, text="Scan for CSRF", command=self.scan_csrf, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2)
        self.csrf_button.grid(row=4, column=0, padx=10, pady=5)

        self.open_redirect_button = ctk.CTkButton(self, text="Scan for Open Redirect", command=self.scan_open_redirect, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2)
        self.open_redirect_button.grid(row=4, column=1, padx=5, pady=5)

        self.command_injection_button = ctk.CTkButton(self, text="Scan for Command Injection", command=self.scan_command_injection, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2)
        self.command_injection_button.grid(row=5, column=0, padx=5, pady=5)

        self.file_upload_button = ctk.CTkButton(self, text="Scan for File Upload", command=self.scan_file_upload_vulnerabilities, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2)
        self.file_upload_button.grid(row=5, column=1, padx=5, pady=5)

        self.response_splitting_button = ctk.CTkButton(self, text="Scan for HTTP Response Splitting", command=self.scan_http_response_splitting, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2)
        self.response_splitting_button.grid(row=6, column=0, padx=5, pady=5)

        self.path_traversal_button = ctk.CTkButton(self, text="Scan for Path Traversal", command=self.scan_path_traversal, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2)
        self.path_traversal_button.grid(row=6, column=1, padx=5, pady=5)

        self.clickjacking_button = ctk.CTkButton(self, text="Scan for Clickjacking", command=self.scan_clickjacking, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2)
        self.clickjacking_button.grid(row=7, column=0, padx=5, pady=5)

        self.directory_listing_button = ctk.CTkButton(self, text="Scan for Directory Listing", command=self.scan_directory_listing, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2)
        self.directory_listing_button.grid(row=7, column=1, padx=5, pady=5)

        self.report_button = ctk.CTkButton(self, text="Generate Report PDF", command=self.generate_report, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="red", border_width=2)
        self.report_button.grid(row=8, column=0, columnspan=2, pady=10)
        
        self.owasp_button = ctk.CTkButton(self, text="OWASP Test", command=self.scan_OWASPER, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="red", border_width=2)
        self.owasp_button.grid(row=9, column=0, columnspan=2, pady=10)
        
        self.monitor_button_2 = ctk.CTkButton(self, text="Anomaly Detection",command=self.monitor_traffic, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="red", border_width=2)
        self.monitor_button_2.grid(row=10, column=0, columnspan=2, pady=10)
        
        self.monitor_button = ctk.CTkButton(self, text="Live Traffic Monitor", command=self.open_monitor, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="red", border_width=2)
        self.monitor_button.grid(row=11, column=0, columnspan=2, pady=10)

        self.scanner = None

    def monitor_traffic(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("Error", "Invalid URL. Please enter a valid URL.")
            return
        Thread(target=collect_traffic_data, args=(url,), daemon=True).start()
        Thread(target=show_realtime_visuals, args=(url,), daemon=True).start()
        
    def open_monitor(self):
            url = self.url_entry.get()
            if not url:
                ctk.CTkMessageBox.show_error("Error", "Please enter a valid URL.")
            else:
                TrafficMonitorPopup(self, url)
    
    def show_message(self, title, message):
        CustomMessageBox(self, title=title, message=message)
        
    def start_scan(self):
        target = self.url_entry.get()
        self.scanner = WebAppSecurityScanner(target)
        self.scanner.scan_vulnerabilities()
        self.show_message("Scan Complete", "Vulnerability scan completed!")

    def scan_sql(self):
        target = self.url_entry.get()
        self.scanner = WebAppSecurityScanner(target)
        self.scanner.check_sql_injection()
        self.show_message("SQL Injection Scan Complete", "SQL Injection tests completed!")

    def scan_xss(self):
        target = self.url_entry.get()
        self.scanner = WebAppSecurityScanner(target)
        self.scanner.check_xss()
        self.show_message("XSS Scan Complete", "XSS tests completed!")

    def scan_csrf(self):
        target = self.url_entry.get()
        self.scanner = WebAppSecurityScanner(target)
        self.scanner.check_csrf()
        self.show_message("CSRF Scan Complete", "CSRF tests completed!")

    def scan_open_redirect(self):
        target = self.url_entry.get()
        self.scanner = WebAppSecurityScanner(target)
        self.scanner.check_open_redirect()
        self.show_message("Open Redirect Scan Complete", "Open Redirect tests completed!")

    def scan_command_injection(self):
        target = self.url_entry.get()
        self.scanner = WebAppSecurityScanner(target)
        self.scanner.check_command_injection()
        self.show_message("Command Injection Scan Complete", "Command Injection tests completed!")

    def scan_file_upload_vulnerabilities(self):
        target = self.url_entry.get()
        self.scanner = WebAppSecurityScanner(target)
        self.scanner.check_file_upload_vulnerabilities()
        self.show_message("File Upload Vulnerability Scan Complete", "File upload tests completed!")

    def scan_http_response_splitting(self):
        target = self.url_entry.get()
        self.scanner = WebAppSecurityScanner(target)
        self.scanner.check_http_response_splitting()
        self.show_message("HTTP Response Splitting Scan Complete", "HTTP Response Splitting tests completed!")

    def scan_path_traversal(self):
        target = self.url_entry.get()
        self.scanner = WebAppSecurityScanner(target)
        self.scanner.check_path_traversal()
        self.show_message("Path Traversal Scan Complete", "Path Traversal tests completed!")

    def scan_clickjacking(self):
        target = self.url_entry.get()
        self.scanner = WebAppSecurityScanner(target)
        self.scanner.check_clickjacking()
        self.show_message("Clickjacking Scan Complete", "Clickjacking tests completed!")

    def scan_directory_listing(self):
        target = self.url_entry.get()
        self.scanner = WebAppSecurityScanner(target)
        self.scanner.check_directory_listing()
        self.show_message("Directory Listing Scan Complete", "Directory Listing tests completed!")
        
    def scan_OWASPER(self):
        target = self.url_entry.get()
        self.scanner = WebAppSecurityScanner(target)
        self.scanner.run_owasp_zap_scan()
        self.show_message("OWASP Scan Complete", "Owasp tests completed!")

    def generate_report(self):
        if self.scanner:
            self.scanner.generate_report()

if __name__ == "__main__":
    app = App()
    app.mainloop()
