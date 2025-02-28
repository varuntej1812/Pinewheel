# AI Cybersecurity Workflow

## Overview
This project implements an **agentic cybersecurity workflow** using LangGraph and LangChain. It autonomously executes security scans (nmap, gobuster, ffuf, sqlmap) while enforcing user-defined scope constraints.

## Features
- **Scope Enforcement**: Restricts scans to specific domains/IP ranges.
- **Dynamic Task Updates**: Adds new tasks based on scan results.
- **Failure Handling**: Automatically retries failed tasks.
- **Real-Time Logs**: Displays execution progress in real-time.
- **Scan Results**: Stores and displays results in JSON format.

## Setup
1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt

2. **Install Security Tools**:

Nmap,
Gobuster,
FFuf,
SQLMap

3.**Run the application**:

streamlit run streamlit_app.py

System Design

Scope Enforcement:

Validates targets against user-defined domains/IP ranges.

Blocks out-of-scope scans.

Task Execution:

Breaks down high-level tasks into executable steps.

Executes tools sequentially (nmap → gobuster → ffuf → sqlmap).

Failure Handling:

Retries failed tasks up to 3 times.

Logs errors with debug information.

Dynamic Updates:

Adds new tasks based on scan results (e.g., gobuster after nmap).

Limitations:

Limited to basic scans (nmap, gobuster, ffuf, sqlmap).

Requires manual scope configuration.

Performance depends on target responsiveness.

Future Improvements:

Add more security tools (e.g., nikto, wpscan).

Implement parallel task execution.

Add a database for storing scan results.

Improve error handling for edge cases.

Benchmarks:

Average Scan Time: ~2-5 minutes per target.

Scope Adherence: 100% in all test cases.

