
# ⚙️ Features
## 🔐 Authentication

- Register + Login

- Password hashing (bcrypt)

- Access + Refresh tokens

- Optional Redis-backed token blacklist

- Auto-detects if Redis is unavailable

## 🧮 Calculator API

- Add, Subtract, Multiply, Divide

- Stores each calculation in the DB

- Full CRUD (Create, Read, Update, Delete)

- ⭐️ NEW Feature: Exponentiation **

## 🖥️ Frontend (Jinja2)

- Registration page

- Login page

- Dashboard

- Interactive JS-powered calculator

## 📊 Persistent Storage

- All calculations stored in PostgreSQL

- Users see only their own history

- Complete BREAD functionality:

   - Browse
   - Read
   - Edit
   - Add
   - Delete

## 🧪 Testing

- Unit tests

- Integration tests

- Playwright end-to-end browser tests (headless)

- Auto-starts FastAPI test server for e2e

- Automated GitHub Actions CI

---

# 🚀 Getting Started (Local Development)

1. Clone the repository

```
git clone https://github.com/MaxielDJ7/IS601_FinalProject.git


```

2. Create virtual environment

```
python -m venv venv
source venv/bin/activate
```

3. Install dependencies

```
pip install --upgrade pip

pip install -r requirements.txt

```
---
# 🖥️ Run FastAPI Backend (Local)

```
uvicorn app.main:app --reload --port 8000
```
Open in Browser

```
http://127.0.0.1:8000

```
---

# 🐳 Running with Docker (Backend + Postgres + Redis)

```
docker compose up --build

```
| Service    | URL                                            |
| ---------- | ---------------------------------------------- |
| FastAPI    | [http://localhost:8000](http://localhost:8000) |
| PostgreSQL | localhost:5432                                 |
| Redis      | localhost:6379                                 |

My Dockerhub: https://hub.docker.com/r/maxieldj7/is601_finalproject

# 🧪 Running Tests

## 🔹 Run All Tests

```
pytest -vv

```

## 🎭 Playwright End-to-End Tests


Run all E2E tests:
```
pytest tests/e2e -vv
```

# 🤖 GitHub Actions CI/CD

![CI](https://github.com/MaxielDJ7/IS601_FinalProject/actions/workflows/test.yml/badge.svg)
