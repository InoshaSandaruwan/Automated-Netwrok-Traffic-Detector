### **Updated Project Overview:**

In this project, I developed a **Network Traffic Detection System** that helps identify suspicious or malicious network traffic in real-time. The system is built using **Wireshark**, **Scapy**, and **Python** to analyze network packets. It focuses on detecting network threats such as **port scans**, **UDP scans**, **ICMP traffic**, and other **anomalous activities** that might indicate attacks or security breaches in a network environment.

With this system, network traffic is continuously monitored, and when abnormal patterns are detected, real-time alerts are generated to provide immediate notification. This helps network administrators and security professionals quickly identify potential issues and take preventive actions.

---

### **Key Features (Updated):**

1. **Port Scan Detection (TCP/UDP)**:
   - Detects **TCP** and **UDP port scans**, which are often used by attackers to probe open ports for vulnerabilities.
   - The system alerts administrators when these types of scans are detected.

2. **Anomalous Traffic Detection**:
   - The system analyzes network traffic for unusual patterns such as sudden spikes in traffic or irregular communication between hosts.
   - Alerts are triggered when anomalous traffic is detected, which could indicate malicious activity or misconfigurations.

3. **ICMP Traffic Detection**:
   - Monitors **ICMP traffic** (e.g., **ping** requests) and detects excessive or suspicious pinging that could be indicative of **DDoS** attacks or other malicious behavior.

4. **ARP (Address Resolution Protocol) Detection**:
   - Detects **ARP spoofing** or **ARP poisoning** attacks, which can be used to intercept or alter network traffic.

5. **Real-Time Monitoring and Alerting**:
   - Provides live monitoring of network packets.
   - Generates **real-time alerts** when suspicious or anomalous activities are detected.

6. **Automated Logging**:
   - All detected threats are logged with detailed information into an **alert log file**, which can be reviewed by network administrators.

---

### **Technologies Used:**

- **Wireshark**: Network protocol analyzer for capturing and inspecting packets.
- **Scapy**: Python library for packet manipulation and analysis.
- **Python**: The programming language used for implementing the detection logic and alert system.

