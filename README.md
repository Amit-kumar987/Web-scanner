# Web Security Scanner

A Python tool that audits a website's **HTTP security headers, cookie flags and CORS configuration**, then gives each site a severity-ranked list of problems, fix recommendations, a score out of 100 and a grade (A-F).

## Project Description
Many common web attacks (XSS, clickjacking, session theft, cross-origin data theft) can be prevented or reduced with a few response headers and cookie settings, but they are easy to forget. This project automates the check. The scanner sends safe, read-only requests (GET and OPTIONS) and tests:

- **Security headers:** Strict-Transport-Security, Content-Security-Policy, X-Frame-Options / frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Information leaks:** version details in `Server` and `X-Powered-By`
- **Cookies:** `HttpOnly`, `Secure`, `SameSite`
- **CORS:** reflected origins, wildcard origin, `null` origin, risky preflight methods

The notebook includes three small local test servers (insecure, partially secured, hardened) so results are repeatable and can be checked against known answers.

## Dataset
No external dataset is needed. The scan targets are the three local test servers the notebook starts itself. You can optionally add your own sites in section 5 of the notebook.

Reference material used to choose the checks:
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN, Cross-Origin Resource Sharing (CORS): https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/

## Technologies Used
Python 3.9+, Jupyter Notebook, requests, pandas, NumPy, matplotlib, seaborn, python-docx, pytest, `http.server` and `argparse` (standard library).

## Setup and Run
```bash
# 1. clone the repository and enter the folder
git clone <your-repo-url>
cd <your-repo-folder>

# 2. (optional) create a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. install dependencies
pip install -r requirements.txt

# 4. open the notebook and run all cells
jupyter notebook AmitKumar_WebSecurityScanner.ipynb
```
No internet connection is needed for the default run. The last cell of the notebook writes the report `AmitKumar_ProjectReport.docx`.

### Scanning your own site
In section 5, set `EXTERNAL_TARGETS = {"my-site": "https://example.com/"}`, then re-run sections 3 and 4.

> **Only scan sites you own or have written permission to test.**

### Command-line use
The scanner also works without Jupyter:
```bash
python scan.py --lab                                   # scan the built-in test servers
python scan.py https://example.com/                    # scan a site you own or may test
python scan.py https://example.com/ --json out.json --csv out.csv --fail-on High
```
`--fail-on High` makes the command exit with code 1 if a High finding exists, so it can be used in a CI/CD pipeline.

### Run the tests
```bash
python -m pytest -q
```
The tests start the local lab servers and check that scores, grades and individual findings match what each server was built to show. They also run automatically on GitHub through `.github/workflows/tests.yml`.

## Outputs
Created in `results/` when the notebook runs: `findings.csv`, `scan_results.json`, `scores.png`, `severity.png`, `check_matrix.png`.

## Key Information
- **Scoring:** start at 100; High = -20, Medium = -10, Low = -4. Grades: A >= 90, B >= 80, C >= 65, D >= 50, F below 50.
- **Validation:** a self-check cell asserts that the scanner reports the expected findings for each test server.
- **Limitations:** passive checks only (no exploitation); checks only the URL given; results are a snapshot in time.
- **Possible extensions:** multi-page crawling, TLS checks, command-line interface, running in a CI/CD pipeline.

## Project Structure
```
.
|-- AmitKumar_WebSecurityScanner.ipynb   # complete project code (notebook)
|-- AmitKumar_ProjectReport.docx         # project report
|-- README.md
|-- requirements.txt
|-- scan.py                              # command-line interface
|-- web_scanner/
|   |-- scanner.py                       # header, cookie and CORS checks, scoring
|   `-- lab_servers.py                   # local test servers (insecure / partial / hardened)
|-- tests/
|   `-- test_scanner.py                  # automated tests
|-- results/                             # sample output from a scan of the lab servers
|-- .github/workflows/tests.yml          # runs the tests on every push
|-- LICENSE                              # MIT
`-- .gitignore
```
