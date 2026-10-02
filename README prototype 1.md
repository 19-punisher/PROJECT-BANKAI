# BANKAI / VPNGuard

Controlled local SOC/authentication-security lab built as a single Python application.

BANKAI detects authentication attack **patterns** such as:

- Brute Force
- Password Spraying
- VPN / Password Spray
- Impossible Travel
- Secondary behavioral anomalies with Isolation Forest

The application persists authentication events, alerts and incidents in SQLite and exposes browser-based SOC views.

> **Safety:** BANKAI is a controlled/private lab prototype. The attacker/client flow is restricted to local, private, and test-address ranges. Do not point it at public or third-party systems.

---

## Repository contents

This repository intentionally stays small:

```text
BANKAI/
├── BANKAI_prototype.py
└── README.md
```

No database, model, cache, or runtime files need to be committed. BANKAI stores its runtime state under the user's local application-data directory.

---

# 1. Requirements

## Windows

You need:

- Python 3.10 or newer
- Chrome, Edge, or another modern browser
- For multi-laptop mode: a reachable LAN/Wi-Fi/hotspot network
- Windows Firewall access when allowing another laptop to connect

External Python packages:

- `pandas`
- `scikit-learn`

The application uses Python's standard library for HTTP, SQLite, GUI, networking, JSON, threading, and CSV handling.

No Docker, Kafka, Kubernetes, Redis, FastAPI, Uvicorn, or other extra services are required.

---

# 2. Clone the Git repository

After the project is pushed to GitHub, clone it with:

```powershell
git clone <YOUR-GITHUB-REPO-URL>
cd BANKAI
```

Example:

```powershell
git clone https://github.com/YOUR_USERNAME/BANKAI.git
cd BANKAI
```

Confirm the two files are present:

```powershell
dir
```

You should see:

```text
BANKAI_prototype.py
README.md
```

---

# 3. Install dependencies

Check Python:

```powershell
python --version
```

If `python` is not available, try:

```powershell
py --version
```

Install dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install pandas scikit-learn
```

Verify them:

```powershell
python -c "import pandas, sklearn; print('Dependencies OK')"
```

---

# 4. IMPORTANT — run the self-test first

Before starting the GUI, verify the build:

```powershell
python BANKAI_prototype.py --self-test
```

A successful run should report the application's actual test results, including:

```text
BANKAI SELF-TEST: PASS
Real HTTP client -> target -> gateway -> sentinel -> detection: OK
Brute force + VPN spray + impossible travel: OK
Isolation Forest: OK
All-in-One route + 3-section page structure: OK
User dataset evaluation endpoint: OK
Target protective shutdown alert: OK
```

Do not manually type or claim test results that the application did not produce.

---

# 5. SINGLE LAPTOP / ALL-IN-ONE MODE

This is the easiest way to run BANKAI.

Everything runs on one machine, while the browser uses **one All-in-One tab** containing three live sections:

```text
+----------------+----------------+----------------------+
| 01 / ATTACKER  | 02 / OBSERVER  | 03 / TARGET SERVER   |
+----------------+----------------+----------------------+
```

The gateway runs in the background.

## Step 1 — Start Control Center

```powershell
python BANKAI_prototype.py
```

The BANKAI SOC Control Center opens.

## Step 2 — Select the mode

Choose:

```text
Single Laptop — All-in-One
```

Keep the local defaults:

```text
Laptop 2 Sentinel IP       127.0.0.1
Laptop 1 Auth/Gateway IP   127.0.0.1
Laptop 3 Client IP         127.0.0.1
Dashboard API Token        BANKAI-DASHBOARD-2026
```

## Step 3 — Setup

Click:

```text
Setup / Repair Environment
```

This initializes the local SQLite environment.

## Step 4 — Diagnose

Click:

```text
Self-Test / Diagnose
```

The Control Center should report `SELF-TEST PASS` when the application's own test suite passes.

## Step 5 — Start

Click:

```text
Start Selected Role
```

Single Laptop mode starts these local services:

```text
Observer  :8000
Gateway   :8100
Target    :8200
Attacker  :8300
```

Then the application opens **one browser tab** for All-in-One.

## Step 6 — Test a normal login

The lab contains provisioned demo accounts. Example:

```text
Username: alice@company.local
Password: Alice123!
```

Expected:

```text
HTTP 200
```

Use a wrong password to test the failure path:

```text
HTTP 401
```

These credentials are **lab-only demo credentials**, not real user credentials. Never replace them with real passwords before publishing the repository.

## Step 7 — Understand the real request pipeline

The All-in-One page exposes the live pipeline:

```text
Browser
  -> Target Auth :8200
  -> Gateway :8100
  -> Sentinel / Observer :8000
  -> SQLite
  -> Detection Engine
  -> Alert / Incident
```

## Step 8 — Run controlled attack scenarios

Use the **ATTACKER** section for:

```text
Normal Login
Brute Force Lab
VPN / Password Spray
Impossible Travel
```

The generated requests go through the actual local application pipeline. The resulting events, alerts, and incidents are backend-derived rather than injected only with browser JavaScript.

## Step 9 — Observe the result

The **OBSERVER** section shows live backend data such as:

- events
- alerts
- incidents
- critical count
- attack distribution
- activity over time
- Isolation Forest status
- geo activity
- evaluation information when available

The **TARGET SERVER** section shows:

- authentication status
- gateway status
- Sentinel status
- current protection risk
- recent target events
- HTTP 200 / 401 authentication result
- protection/shutdown alert state

---

# 6. THREE-LAPTOP / MULTI-LAPTOP MODE

Use this mode when the physical roles are split across three laptops.

## Roles

```text
Laptop 3  -> Attacker / Lab Client
Laptop 1  -> Target Authentication + Gateway
Laptop 2  -> Sentinel + SQLite + SOC Observer
```

Conceptual flow:

```text
Laptop 3
Attacker / Client
     |
     | real HTTP authentication
     v
Laptop 1
Target Auth :8200
     |
     | Gateway forwarding
     v
Gateway :8100
     |
     | Sentinel ingestion
     v
Laptop 2
Observer :8000
     |
     v
SQLite + Detection
     |
     v
Alerts / Incidents / SOC Dashboard
```

---

## 6.1 Network example

One supported topology is:

```text
Laptop 3
  | Wi-Fi / phone hotspot
  v
Laptop 1
  | Ethernet / LAN
  v
Laptop 2
```

Laptop 1 may therefore need both Wi-Fi and Ethernet connectivity.

The exact IP addresses depend on your network. Use the actual addresses assigned to each laptop.

Example only:

```text
Laptop 1 Auth/Gateway IP : 192.168.1.20
Laptop 2 Sentinel IP      : 192.168.1.30
Laptop 3 Client IP        : 192.168.1.40
```

These are example addresses. Do not copy them blindly.

---

# 7. MULTI-LAPTOP — LAPTOP 1

Laptop 1 runs the Target Auth and Gateway roles.

## Step 1

Clone the same repository:

```powershell
git clone <YOUR-GITHUB-REPO-URL>
cd BANKAI
python -m pip install pandas scikit-learn
```

## Step 2

Run the self-test locally:

```powershell
python BANKAI_prototype.py --self-test
```

## Step 3

Start the Control Center:

```powershell
python BANKAI_prototype.py
```

Select:

```text
Laptop 1 — Auth + Gateway
```

Enter Laptop 1's network IP configuration as appropriate for your setup.

Start the selected role.

The relevant services are:

```text
Gateway :8100
Target  :8200
```

The Control Center can also test connectivity.

---

# 8. MULTI-LAPTOP — LAPTOP 2

Laptop 2 runs Sentinel + SQLite + the SOC observer/dashboard.

## Step 1

Clone and install:

```powershell
git clone <YOUR-GITHUB-REPO-URL>
cd BANKAI
python -m pip install pandas scikit-learn
```

## Step 2

Run:

```powershell
python BANKAI_prototype.py --self-test
```

## Step 3

Start the Control Center:

```powershell
python BANKAI_prototype.py
```

Select:

```text
Laptop 2 — Sentinel + Dashboard
```

Set the configuration to match the actual Laptop 1 and Laptop 3 addresses where required.

Start the role.

The Observer service is:

```text
:8000
```

Open the displayed SOC dashboard on Laptop 2.

---

# 9. MULTI-LAPTOP — LAPTOP 3

Laptop 3 runs the controlled attacker/client interface.

## Step 1

Clone and install:

```powershell
git clone <YOUR-GITHUB-REPO-URL>
cd BANKAI
python -m pip install pandas scikit-learn
```

## Step 2

Run:

```powershell
python BANKAI_prototype.py --self-test
```

## Step 3

Start the Control Center:

```powershell
python BANKAI_prototype.py
```

Select:

```text
Laptop 3 — Client
```

Configure the Laptop 1 target/gateway address.

Start the role.

The attacker/client service is:

```text
:8300
```

Use the attacker page to send controlled authentication requests to the configured private/test target.

---

# 10. FIREWALL / CONNECTIVITY

If another laptop cannot connect, first confirm the services are actually listening and healthy.

On each relevant laptop, use the Control Center:

```text
Test Wi-Fi / LAN Connectivity
```

Health endpoints are:

```text
Observer  http://<observer-ip>:8000/health
Gateway   http://<gateway-ip>:8100/health
Target    http://<target-ip>:8200/health
Attacker  http://<client-ip>:8300/health
```

Windows Firewall may need an inbound rule for the BANKAI Python process or the relevant TCP ports.

Typical BANKAI ports:

```text
8000  Observer / Sentinel
8100  Gateway
8200  Target Auth
8300  Attacker / Client
```

Only expose these ports on your private lab network.

Do not expose BANKAI directly to the public internet.

---

# 11. DATASET LAB

BANKAI can evaluate a user-supplied CSV.

The application expects core fields such as:

```text
status
username
source_ip
```

Optional fields can include:

```text
timestamp / time / ts / datetime
latitude / lat
longitude / lon / lng
ground_truth_label / ground_truth / label
```

Example:

```csv
status,username,source_ip,ground_truth_label
401,alice@company.local,10.0.0.81,ATTACK_BRUTE_FORCE
401,alice@company.local,10.0.0.81,ATTACK_BRUTE_FORCE
200,bob@company.local,10.0.0.24,NORMAL
```

Ground-truth labels are used **after detection** for evaluation/scoring rather than being fed directly into the detection rules.

The Dataset Lab can provide measured results such as:

- Precision
- Recall
- F1
- FPR
- incident-level metrics
- Alert-to-True-Positive ratio when applicable

These are dataset-evaluation results. They are not automatically real-world production accuracy numbers.

---

# 12. RUNTIME DATA

BANKAI keeps runtime state outside the Git repository, including:

- SQLite database
- Isolation Forest model files
- control-center configuration
- other runtime application state

On Windows this is stored under the user's local application-data area.

This means you can safely clone or update the Git repository without committing your local database/history.

---

# 13. TROUBLESHOOTING

## `python` command not found

Try:

```powershell
py --version
py -m pip install pandas scikit-learn
```

Then run:

```powershell
py BANKAI_prototype.py --self-test
```

## Dependency error

Run:

```powershell
python -m pip install --upgrade pip
python -m pip install pandas scikit-learn
```

## Port already in use

BANKAI uses:

```text
8000 / 8100 / 8200 / 8300
```

Stop an older BANKAI instance before starting another one, or identify the process using the port.

## Multi-laptop target is unreachable

Check:

1. Both laptops are actually on the same reachable network path.
2. The configured IP address is the current IP address.
3. BANKAI is listening on the configured interface.
4. Windows Firewall is not blocking the connection.
5. The relevant `/health` endpoint responds.

## Dashboard says API OFFLINE

First check:

```text
http://<observer-ip>:8000/health
```

Then use the Control Center connectivity test.

## Self-test fails

Run:

```powershell
python BANKAI_prototype.py --self-test
```

Copy the exact failure line. Do not assume the system passed if the self-test failed.

---

# 14. DEVELOPMENT RULE

For every code modification to BANKAI:

```text
CHANGE CODE
   ↓
COMPILE CHECK
   ↓
SELF-TEST
   ↓
RELEVANT INTEGRATION TESTS
   ↓
ONLY THEN CALL THE CHANGE VERIFIED
```

At minimum, changes affecting the backend should be checked against the relevant authentication, detection, SQLite, API, and frontend integration paths.

Never claim a test passed unless it was actually run.

---

# 15. CURRENT VERIFICATION STATUS

The local build has been verified for:

- Python compilation
- built-in self-test
- real local HTTP authentication
- HTTP 200 / 401 behavior
- brute-force detection path
- VPN/password-spray detection path
- impossible-travel detection path
- Isolation Forest path
- SQLite persistence
- All-in-One route and 3-section page structure
- dataset evaluation/training/analyze API paths
- target protection/shutdown alert logic

Physical testing of a real three-laptop Wi-Fi + Ethernet/hotspot topology is a separate hardware/network validation step and must not be claimed as completed until actually performed.

---

# 16. PUSHING THIS PROJECT TO GITHUB

From the repository folder:

```powershell
git init
git add BANKAI_prototype.py README.md
git commit -m "Add BANKAI VPNGuard prototype"
git branch -M main
git remote add origin <YOUR-GITHUB-REPO-URL>
git push -u origin main
```

After the first push, normal updates are:

```powershell
git add BANKAI_prototype.py README.md
git commit -m "Update BANKAI prototype"
git push
```

Before every push, run:

```powershell
python BANKAI_prototype.py --self-test
```

Then check the Git diff:

```powershell
git diff -- BANKAI_prototype.py README.md
```

Only push changes you have actually verified.

---

## License / project note

Add the project's chosen license here before public distribution if required by your team, college, or hackathon.
