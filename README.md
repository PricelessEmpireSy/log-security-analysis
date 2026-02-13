# Log Security Analysis - Mini SOC Project

## Overview

A hands-on cybersecurity analyst project analyzing web server logs for threats like brute-force attacks and suspicious endpoints. Built with Python, VS Code, and GitHub.

## Detections Implemented

- Top request-making IPs (high-volume traffic)
- Brute-force: IPs with >10 failed logins (401 status)
- Suspicious access: Hits to /admin, /login, /wp-login.php

## Setup & Run

1. Clone repo
2. pip install -r requirements.txt (or none needed)
3. python analyze_logs.py
4. Check outputs/results.csv and console output

## Sample Data

Uses realistic Apache-style web logs in data/sample.log. [web:20]

Extend: Add your own logs or Windows event JSON.

Author: MERCY A AGBAYI
