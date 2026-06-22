# 🛡️ Web Application Firewall (WAF)

> A lightweight Python-based Web Application Firewall designed to detect, analyze, and block malicious HTTP requests before they reach a vulnerable web application.

## Overview

The WAF acts as a reverse proxy sitting in front of DVWA (Damn Vulnerable Web Application), inspecting incoming HTTP requests and deciding whether they should be:

✅ Allowed

⚠️ Flagged as suspicious

🚫 Blocked before reaching the target

The project was developed as part of the **CYB333 Cyber Threats** course and explores how web application firewalls can defend against common web attacks using multiple detection techniques.

---

## 🚦 How It Works

```text
Attacker / User
        │
        ▼
┌─────────────────┐
│      WAF        │
│  (Port 8080)    │
└─────────────────┘
        │
        ▼
┌─────────────────┐
│      DVWA       │
│  Vulnerable App │
└─────────────────┘
```

Every request passes through the WAF first.

The WAF analyzes the request, checks for malicious patterns, calculates a risk score, and decides whether the request should continue to the backend application.

---

## 🔍 Detection Techniques

### Signature-Based Detection

The WAF uses regular expression signatures loaded dynamically from `rules.txt`.

This allows attack signatures to be updated without modifying the source code.

Examples include:

* Cross-Site Scripting (XSS)
* SQL Injection
* Path Traversal
* Command Injection
* Base64 Backdoor Patterns
* Database Delay Attacks
* Large Payload / DoS Signatures

---

### 📊 Score-Based Detection

Not every attack is obvious.

Instead of relying only on exact signatures, the WAF assigns risk points to suspicious behavior.

Example:

| Pattern                    | Score |
| -------------------------- | ----- |
| XSS Script                 | 3     |
| SQL Boolean Attack         | 3     |
| Path Traversal             | 2     |
| Command Injection Keywords | 2     |

Requests exceeding a predefined threshold are automatically blocked.

---

### 🍯 Honeypot Detection

The WAF contains hidden trap parameters that legitimate users should never touch.

If a request interacts with these hidden values, it is immediately treated as suspicious and blocked.

---

## 📋 Logging & Monitoring

Every request is recorded and categorized as:

| Status  | Description                  |
| ------- | ---------------------------- |
| ALLOWED | Clean request                |
| FLAGGED | Suspicious behavior detected |
| BLOCKED | Confirmed malicious request  |

Each log entry includes:

* Source IP
* Requested path
* Timestamp
* Detection score
* Request status

---

## 📈 Dashboard

A lightweight Flask dashboard provides visibility into WAF activity.

Features include:

* Traffic summary
* Allowed requests count
* Blocked requests count
* Flagged requests count
* Request history table

The dashboard transforms raw logs into an easy-to-read security overview.

---

## 🧪 Testing

The project includes an automated testing script (`test.sh`) that simulates both normal and malicious traffic.

Test cases include:

* Normal Requests
* SQL Injection
* Cross-Site Scripting (XSS)
* Path Traversal
* Command Injection
* Honeypot Triggers
* Database Delay Attacks
* Large Payload Attacks

### Example Log Entries
The WAF records every request and classifies it as ALLOWED, FLAGGED, or BLOCKED.
```
FLAGGED: 192.168.56.107 dvwa/vulnerabilities/xss_r/ 2025-11-21 19:31:35  4 
ALLOWED: 192.168.56.104 dvwa 2025-11-22 17:36:20  0 
BLOCKED: 192.168.56.104 dvwa/ 2025-11-22 17:37:31  10 
```

### Dashboard Results
<img width="442" height="300" alt="image" src="https://github.com/user-attachments/assets/d6f9a7d9-02e1-4e5b-b6ea-f7eaf67fd467" />

---

## 🛠️ Technologies Used

* Python
* Flask
* Requests
* Regular Expressions (Regex)
* HTML
* DVWA (Damn Vulnerable Web Application)

---

## 🎯 Skills Demonstrated

* Web Application Security
* Secure Proxy Design
* Threat Detection
* Security Monitoring
* Log Analysis
* Python Development
* Flask Applications
* Signature-Based Detection
* Defensive Security Concepts

---

## 👥 Team Members

* Shouq Aljohani
* Lama Alowaydhi
* Layan Alaboudi

---

## ⚠️ Disclaimer

This project was developed in a controlled educational environment for defensive cybersecurity learning purposes.

All attack simulations were performed against intentionally vulnerable systems designed for security training.
