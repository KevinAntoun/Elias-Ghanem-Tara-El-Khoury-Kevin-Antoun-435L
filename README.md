# Security Incident Detection and Response Management System

**Software Tools Lab (435L) — Sprint 1 | Python / Flask Backend**

**Team:** Tara El Khoury · Elias Ghanem · Kevin Antoun

[**API Documentation (GitHub Pages)**](https://kevinantoun.github.io/Elias-Ghanem-Tara-El-Khoury-Kevin-Antoun-435L/) · [**Source Code**](https://github.com/KevinAntoun/Elias-Ghanem-Tara-El-Khoury-Kevin-Antoun-435L) · [**GitHub Actions**](https://github.com/KevinAntoun/Elias-Ghanem-Tara-El-Khoury-Kevin-Antoun-435L/actions)

> **Documentation availability:** The GitHub Pages link works after the repository's Pages deployment has been configured and completed successfully. You can always build and view the same documentation locally using the instructions below.

## Overview

The Security Incident Detection and Response Management System is an academic, API-based backend for tracking cybersecurity incidents and coordinating security operations. It brings together user and role management, IT assets, incident investigations, threat intelligence, audit logs, vulnerability tracking, notifications, response playbooks, and security reports.

The project comprises **nine Flask REST services**, each with its own local development port. Each exposes JSON endpoints, uses shared infrastructure, and can communicate with other services over HTTP. A shared SQLite database supports the relational data model for this coursework project.

There is no required frontend for Sprint 1. The APIs can be exercised using **Postman** and **pytest**, and their Python reference documentation is generated with **Sphinx**.

## Services

| # | Service | Module | Default port | Main responsibility |
| --- | --- | --- | --- | --- |
| 1 | Users & Identity | `services/users` | `5001` | Accounts, authentication, profiles, and roles |
| 2 | Asset Management | `services/assets` | `5002` | IT asset inventory, ownership, and criticality |
| 3 | Incident Management | `services/incidents` | `5003` | Incident reporting, assignment, investigation, and status |
| 4 | Threat Intelligence | `services/threats` | `5004` | Threat indicators, severities, and related intelligence |
| 5 | Security Audit Logging | `services/audit` | `5005` | Security events, activity history, and accountability |
| 6 | Security Reports | `services/reports` | `5006` | Aggregated security data and reporting |
| 7 | Vulnerability Management | `services/vulnerabilities` | `5007` | Vulnerabilities, affected assets, and remediation |
| 8 | Notifications & Alerts | `services/notifications` | `5008` | Alerts, user notifications, and read status |
| 9 | Response Playbooks | `services/playbooks` | `5009` | Incident-response procedures and action progress |

The Sprint 1 specification defines **six core API operations per service (54 total)**. Refer to the generated API documentation and each service's `routes.py` for the actual route signatures and behavior. A successful health check verifies a service is reachable, not that every business workflow has been tested end to end.

## Technology stack

| Area | Technology |
| --- | --- |
| Language | Python 3.11+ |
| REST APIs | Flask |
| Database | SQLite (`sqlite3`) |
| Service communication | HTTP / JSON (`requests`) |
| Authentication | JWT-based authentication and role-based authorization |
| API testing | Postman |
| Automated testing | pytest |
| Documentation | Python docstrings + Sphinx |
| CI and docs publishing | GitHub Actions + GitHub Pages |
| Collaboration | Git + GitHub pull requests |

## Architecture

```text
               Postman / HTTP API clients
                           |
                           v
              +--------------------------+
              | Nine independent Flask   |
              | services (ports 5001–9)  |
              +--------------------------+
                       |          |
                       |          +---- HTTP / JSON between services
                       v
              +--------------------------+
              | Shared SQLite database   |
              | database/security_       |
              | incidents.db             |
              +--------------------------+
```

All services are in one repository. The `shared/` package provides common app setup, database access, configuration, HTTP helpers, and authentication-related code. The shared database is a deliberate simplification for an academic project; service-to-service business interactions should use the services' HTTP APIs rather than importing another service's route functions.

## Repository layout

```text
.
├── .github/workflows/    # CI and (when configured) documentation publishing
├── database/            # Schema and database initialization
├── docs/                # Sphinx configuration and source pages
├── postman/             # Postman collections
├── scripts/             # Multi-service launcher and health checks
├── services/
│   ├── users/
│   ├── assets/
│   ├── incidents/
│   ├── threats/
│   ├── audit/
│   ├── reports/
│   ├── vulnerabilities/
│   ├── notifications/
│   └── playbooks/
├── shared/              # Shared application infrastructure
├── tests/               # Automated tests
├── .env.example         # Template for local environment settings
├── .gitignore
├── requirements.txt
└── README.md
```

## Getting started

### Prerequisites

- Python **3.11 or newer** and Git.
- Postman (optional, for manually testing API calls).

Run the following commands from a terminal. Use the **repository root** as the working directory for subsequent Python commands.

### 1. Clone the repository

```bash
git clone https://github.com/KevinAntoun/Elias-Ghanem-Tara-El-Khoury-Kevin-Antoun-435L.git
cd Elias-Ghanem-Tara-El-Khoury-Kevin-Antoun-435L
```

### 2. Create and activate a virtual environment

**Windows PowerShell:**

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies and configure `.env`

```bash
python -m pip install -r requirements.txt
```

Copy the provided template:

**Windows PowerShell:**

```powershell
Copy-Item .env.example .env
```

**macOS / Linux:**

```bash
cp .env.example .env
```

Set `JWT_SECRET` in your **local** `.env` to a securely generated value. For example:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Paste the generated value into `JWT_SECRET`. The `.env.example` file also lists `HOST`, `DATABASE_PATH`, and the default ports for all nine services. Keep your `.env`, database files, and credentials out of version control.

### 4. Initialize the database

```bash
python -m database.init_db
```

The local database is configured by `DATABASE_PATH` (the default is `database/security_incidents.db`). Initialization creates the schema for a new database; do not assume it migrates an existing database after schema changes. Back up any data you need before reinitializing during development.

### 5. Start the services

Start all nine local Flask applications:

```bash
python -m scripts.run_all
```

Or start a single service, for example:

```bash
python -m services.users.app
```

Leave the server terminal running while sending requests. Press **Ctrl+C** to stop the launcher. Inter-service operations require the corresponding dependency services to be available.

### 6. Verify the installation

In another terminal (with the virtual environment active):

```bash
python -m scripts.check_services
python -m pytest -q
```

Example health endpoint:

```http
GET http://127.0.0.1:5001/health
```

A healthy response resembles:

```json
{
  "status": "ok",
  "service": "users"
}
```

If a check fails, confirm that the correct processes are running, the corresponding port is not already in use, and your `.env` values are configured correctly.

## Authentication and authorization

The project distinguishes four roles:

| Role | Intended access |
| --- | --- |
| Security Administrator | Manage authorized users, security data, and administrative operations |
| Security Analyst | Investigate assigned incidents and carry out permitted response activities |
| Regular Employee / User | Manage personal data, submit incidents, and view permitted records |
| Auditor | Read-only access to authorized records and reports |

Protected endpoints should verify authentication and enforce role and ownership restrictions. Public registration must not allow users to grant themselves privileged roles. Do not put JWT signing keys, passwords, or real tokens in README examples or Postman collections committed to the repository.

**Initial administrator setup:** Do not assume a default administrator username/password exists. Provision an administrator using the project's authorized setup procedure before performing administrator-only operations; confirm this separately from automated tests.

## Testing

Run the automated test suite from the repository root:

```bash
python -m pytest -q
```

Run live service health checks **after starting the services**:

```bash
python -m scripts.check_services
```

For manual API testing, import the collection provided under `postman/` into Postman. Include valid input, invalid input, authorization failures, and expected response codes when verifying routes. Automated tests and health checks are complementary; passing tests should not be taken as proof of deployment readiness or complete cross-service integration.

## API documentation

**Online:** [Browse the Sphinx API documentation on GitHub Pages](https://kevinantoun.github.io/Elias-Ghanem-Tara-El-Khoury-Kevin-Antoun-435L/)

**Build locally:**

```bash
python -m sphinx -b html docs docs/_build/html
```

Then open `docs/_build/html/index.html` in your browser.

The documentation sources (`docs/*.rst`, `docs/conf.py`, and Python docstrings) are tracked in Git. Sphinx generates the HTML under `docs/_build/html/`. This build directory is intentionally excluded from version control: generated pages can be reproduced and should not cause noisy pull requests or merge conflicts.

**Publishing:** When GitHub Pages is configured to use **GitHub Actions**, a documentation deployment workflow can build Sphinx and publish the HTML from `main`. Check the [Actions tab](https://github.com/KevinAntoun/Elias-Ghanem-Tara-El-Khoury-Kevin-Antoun-435L/actions) for a successful deployment. GitHub Pages hosts **documentation only**, not the running Flask services.

## Collaboration

The project is developed by **Tara El Khoury, Elias Ghanem, and Kevin Antoun**.

Use feature branches and pull requests for changes to services, tests, shared infrastructure, and documentation. Coordinate edits to `shared/`, `database/schema.sql`, and service-to-service API contracts; review and test changes before merging into `main`.

## Project scope and limitations

This is a **coursework backend**, not a production security monitoring product. In particular:

- All nine services share a local SQLite database for simplicity.
- The Flask launcher is intended for local development, not production hosting.
- Service health checks and unit tests do not replace a full review of authorization, integration, or security behavior.
- The generated Sphinx site is reference documentation; it does not run the API.

For detailed endpoint behavior, consult the source code, tests, and published documentation rather than relying solely on the high-level summaries in this README.
