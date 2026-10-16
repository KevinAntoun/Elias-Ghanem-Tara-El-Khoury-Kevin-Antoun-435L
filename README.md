# Security Incident Detection and Response Management System

**Software Tools Lab — Sprint 1 | Backend Project**

**Team:** Tara El Khoury · Elias Ghanem · Kevin Antoun

## Overview

The **Security Incident Detection and Response Management System** is a Python-based backend for managing cybersecurity incidents across an organization. It is designed to help authorized users report and investigate security events, track affected IT assets and vulnerabilities, consult threat indicators, coordinate response procedures, and maintain an auditable record of important actions.

The project is organized into **nine independent REST services**. Each service runs as a separate Flask application and exposes HTTP endpoints that return JSON. Services can communicate with one another through HTTP requests to support workflows spanning multiple security operations. **No frontend is required** for Sprint 1; the APIs are exercised using Postman and automated tests.

> **Development status:** This repository began as a runnable starter scaffold. It includes service entry points, health checks, common utilities, a starter SQLite schema, and a sample inter-service request. The 54 assignment endpoints and their authentication, authorization, validation, business logic, and integration tests must be implemented and verified as development progresses. Do not interpret the list of planned capabilities below as a claim that they are finished.

## Project goals

- Provide a consistent REST API for the full incident lifecycle, from reporting to resolution.
- Enforce role-based access so users can perform only authorized operations.
- Track organizational assets, known threats, and security vulnerabilities.
- Record important system activity and unauthorized access attempts in audit logs.
- Support notifications, response playbooks, and security reports.
- Apply object-oriented design, relational database principles, input validation, version control, testing, and documentation.

## Technology stack

| Area | Technology |
| --- | --- |
| Language | Python 3.11+ |
| REST framework | Flask |
| Database | SQLite (`sqlite3`) |
| Service communication | HTTP / JSON (`requests`) |
| API testing | Postman |
| Automated tests | pytest |
| Documentation | Python docstrings + Sphinx |
| Version control | Git + GitHub |

The starter includes `PyJWT` as a dependency for planned token-based authentication; **authentication is not implemented in the scaffold**.

## Services

Each service is independently runnable on a local development port. The table describes the **intended responsibilities** for Sprint 1.

| # | Service | Folder | Port | Responsibility |
| ---: | --- | --- | ---: | --- |
| 1 | Users & Identity | `services/users` | 5001 | Registration, login, user profiles, account status, roles |
| 2 | Asset Management | `services/assets` | 5002 | Inventory of devices, servers, owners, locations, and criticality |
| 3 | Incident Management | `services/incidents` | 5003 | Incident reporting, analyst assignments, status lifecycle, investigation notes |
| 4 | Threat Intelligence | `services/threats` | 5004 | Known threat indicators including IPs, domains, hashes, and signatures |
| 5 | Security Audit Logging | `services/audit` | 5005 | Security activity, authentication attempts, changes, and access violations |
| 6 | Security Reports | `services/reports` | 5006 | Aggregated statistics about incidents, assets, threats, vulnerabilities, and activity |
| 7 | Vulnerability Management | `services/vulnerabilities` | 5007 | Vulnerabilities, CVE/CVSS details, affected assets, and remediation tracking |
| 8 | Notifications & Alerts | `services/notifications` | 5008 | Security alerts, incident assignment notices, and read/unread tracking |
| 9 | Response Playbooks | `services/playbooks` | 5009 | Ordered incident-response procedures, assigned actions, and execution progress |

The assignment specifies **six core API operations for each service (54 in total)**. Routes are implemented within each service's `routes.py` module, using Flask Blueprints.

## Architecture

```text
                         Postman / HTTP clients
                                   |
                                   v
                  +-----------------------------------+
                  |   Nine independent Flask APIs     |
                  |          ports 5001-5009          |
                  +-----------------------------------+
                        |                     |
                        |                     +-- HTTP/JSON calls to
                        |                         other services
                        v
                  +---------------------------+
                  |  Shared SQLite database   |
                  |  database/security_       |
                  |  incidents.db             |
                  +---------------------------+
```

All services live in **one Git repository**, but each has its own Flask entry point and port. Shared infrastructure code lives in `shared/`.

For this academic project, the services use a **single SQLite database** with related tables and foreign keys. This simplifies the relational schema required by the assignment; it is a deliberate simplification compared with a production microservices design that might use separate data stores. Cross-service **business interactions** should occur through HTTP APIs rather than direct calls to another service's Python functions or modifications to tables owned by other services.

The starter demonstrates HTTP communication with `GET /reports/dependencies`, which checks the Users and Assets health endpoints. This is an **architecture demonstration**, not a graded Reports endpoint.

## Repository structure

```text
.
├── services/
│   ├── users/                  # app.py and routes.py
│   ├── assets/
│   ├── incidents/
│   ├── threats/
│   ├── audit/
│   ├── reports/
│   ├── vulnerabilities/
│   ├── notifications/
│   └── playbooks/
├── shared/
│   ├── app_factory.py          # Flask app creation and JSON error handling
│   ├── auth.py                 # Authentication/authorization integration point
│   ├── config.py               # Environment settings and service ports
│   ├── database.py             # Request-scoped SQLite connection
│   └── service_client.py       # HTTP helper for service-to-service requests
├── database/
│   ├── schema.sql              # Starter tables and foreign keys
│   └── init_db.py              # Database initialization
├── scripts/
│   ├── run_all.py              # Start the nine local Flask processes
│   └── check_services.py       # Check all /health endpoints
├── postman/                    # Starter Postman collection
├── docs/
│   ├── conf.py                 # Sphinx configuration
│   ├── index.rst               # Documentation landing page
│   └── services.rst            # API module reference pages
├── tests/
│   ├── test_health.py          # Service health and error-response smoke tests
│   └── test_schema.py          # Starter database schema tests
├── .env.example
├── requirements.txt
└── README.md
```

Each service's `app.py` launches its Flask application, while `routes.py` defines the service-specific Blueprint and API endpoints.

## Getting started

### Prerequisites

Install **Python 3.11 or newer** and **Git**. Postman is recommended for testing individual requests and inspecting responses.

### 1. Clone the repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd <YOUR_REPOSITORY_FOLDER>
```

Replace the placeholders with the actual GitHub repository URL and folder name.

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

### 3. Install dependencies and configure the environment

```bash
python -m pip install -r requirements.txt
```

Create a local `.env` from `.env.example`:

**Windows PowerShell:**

```powershell
Copy-Item .env.example .env
```

**macOS / Linux:**

```bash
cp .env.example .env
```

The default database path and service ports are defined in `shared/config.py` and may be overridden through environment variables. Do not commit `.env` or secret values.

### 4. Initialize the database

```bash
python -m database.init_db
```

This initializes `database/security_incidents.db` using the starter schema in `database/schema.sql`. The scaffold contains ten main tables: users, assets, incidents, investigation notes, threats, logs, vulnerabilities, notifications, playbooks, and response actions. The schema should be reviewed and extended as features are implemented.

### 5. Start the services

Run all nine applications from the repository root:

```bash
python -m scripts.run_all
```

Or start an individual application while developing:

```bash
python -m services.users.app
```

The launcher is for **local development**, not production deployment. Stop it using **Ctrl+C**. For HTTP calls between services to succeed, both the caller and target services must be running.

## Testing the starter

With the services running, open another terminal and execute:

```bash
python -m scripts.check_services
python -m pytest -q
```

Starter HTTP examples:

```http
GET http://127.0.0.1:5001/health
GET http://127.0.0.1:5003/health
GET http://127.0.0.1:5006/reports/dependencies
```

A healthy service returns JSON similar to:

```json
{
  "status": "ok",
  "service": "users"
}
```

The dependency demonstration checks whether the Users and Assets services respond successfully; it can return **503** if a dependency is unavailable.

Import `postman/sprint1-starter.postman_collection.json` into Postman to run the initial health checks. Expand the collection with each completed assignment endpoint, including valid, invalid, and unauthorized cases. The grader-facing screenshots must show requests and responses from the team's actual running implementation.

## Authentication and access control

The completed system is required to support four roles:

| Role | Intended access |
| --- | --- |
| **Security Administrator** | Manage accounts, assets, incidents, threats, logs, notifications, and response procedures |
| **Security Analyst** | Investigate assigned incidents and work with authorized security data and response actions |
| **Regular Employee/User** | Manage their own profile, report incidents, and view their own reports/notifications |
| **Auditor** | Read-only visibility into permitted records and generation of authorized reports |

Every protected endpoint must authenticate the caller and enforce the role and resource-ownership restrictions in the Sprint 1 specification. Public registration must never allow self-assignment of privileged roles. Passwords must be hashed, account status must be respected, and permission violations must be logged.

**These protections are requirements to implement, not security guarantees provided by the starter.**

## Documentation

Python modules and API endpoints should have descriptive docstrings. Sphinx uses `docs/conf.py`, `docs/index.rst`, and `docs/services.rst` to generate HTML reference pages:

```bash
python -m sphinx -b html docs docs/_build/html
```

Open `docs/_build/html/index.html` locally. Keep endpoint usage examples, request/response formats, expected errors, and Postman evidence accurate as APIs are developed. The generated `docs/_build/` directory is excluded from Git.

## Team collaboration

**Contributors:**

- **Tara El Khoury**
- **Elias Ghanem**
- **Kevin Antoun**

Each member will own **three distinct services**, with assignments agreed upon by the team. Service ownership is deliberately not fixed in this README. Everyone contributes through their own GitHub account, documents their work, and verifies their endpoints.

Recommended workflow:

1. Pull the latest `main` and create a focused feature branch (e.g., `feat/assets-create`).
2. Implement and test changes within the relevant service directory.
3. Coordinate any edits to shared authentication, database schema, and cross-service API contracts.
4. Commit meaningful changes, push the branch, and open a Pull Request.
5. Have another team member review the Pull Request before merging into `main`.

Code and documentation should identify the responsible student where the assignment requires attribution. Any ambiguity about including full names *inside API URLs* should be clarified with the instructor before changing specified route paths.

## Project scope and current limitations

The target Sprint 1 submission includes the nine service implementations, all 54 required endpoints, relational database design, API validation, authentication/authorization, audit logging, real Postman execution evidence, documentation, and a common team report.

The initial scaffold **does not yet implement** the graded business endpoints, authentication, service-wide RBAC, automatic audit events, notification workflows, or report aggregation. As work is merged, update this section to reflect what has actually been implemented and verified.

This project is developed for academic purposes in Software Tools Lab. It is not intended for use as a production security monitoring platform.
