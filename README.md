# LogSentry 🛡️
> A lightweight, robust Python utility for parsing server logs, detecting brute-force attempts, and generating automated security audit reports.

---

## Overview
As web applications and servers scale, monitoring authentication logs manually to spot unauthorized access or brute-force attacks is impractical. **LogSentry** is designed for system administrators, security engineers, and developers who need a fast, dependency-free command-line tool to audit server access logs and flag suspicious activities instantly.

---

## Features
* **Regex-Powered Ingestion:** Efficiently parses standard authentication log formats (such as SSH `auth.log`) to extract timestamps, usernames, and source IP addresses.
* **Configurable Threat Thresholds:** Automatically flags IP addresses exceeding a specified number of failed login attempts.
* **CLI Flexibility:** Built with Python's built-in `argparse` module to support custom log paths and threat thresholds directly from the terminal.
* **Zero External Dependencies:** Built entirely using Python's standard library (`re`, `collections`, `argparse`), making it lightweight and instantly runnable in any environment.

---

## Tech Stack
* **Language:** Python 3.x
* **Core Modules:** `re`, `collections.defaultdict`, `argparse`

---

## Project Structure
```text
logsentry/
│
├── logsentry.py          # Core script containing regex parser and threat engine
├── auth_sample.log       # Sample authentication log for testing
└── README.md             # Project documentation
