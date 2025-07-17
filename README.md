# Aegis

Aegis is a modern web application designed for vulnerability management. It provides a robust backend, built with FastAPI, to help security professionals and developers track, manage, and analyze software vulnerabilities.

## ✨ Features

*   **Project and Asset Management**: Create projects to track different software assets and their associated components.
*   **Dependency Analysis**: Ingest and validate dependency files (starting with `requirements.txt`) to analyze for known vulnerabilities.
*   **Scalable Architecture**: Built with a modular structure using FastAPI's `APIRouter` for easy expansion with new features like vulnerability scanning, reporting, and integration with security feeds.
*   **Containerized Database**: Uses Docker to run a PostgreSQL database for persisting vulnerability and project data.

## 🛠️ Tech Stack

*   **Backend**: Python, FastAPI, Uvicorn
*   **Database**: PostgreSQL
*   **Containerization**: Docker, Docker Compose
*   **Testing**: Pytest, pytest-asyncio

## 📂 Project Structure

A brief overview of the key components of the project:
```
aegis/
├── app/
│   ├── models/
│   ├── routers/
│   ├── services/
│   ├── data/
│   └── main.py
├── db/
│   ├── docker/
│   └── (other db files)
├── tests/
├── mock_osv/
└── requirements.txt
```

## 🚀 Getting Started

Follow these instructions to get the project up and running on your local machine for development and testing purposes.

### Prerequisites

*   Python 3.11+
*   Docker and Docker Compose
*   A Python virtual environment tool (e.g., `venv`)

### 1. Database Setup (Skippable)

> **Note:** For the time being, the application uses in-memory storage for all data. This means that any data you add will be lost when the app is restarted. Persistent storage via PostgreSQL is planned for future releases.

The project uses a PostgreSQL database running in a Docker container. For detailed instructions on setting up and starting the database, please refer to the `db/README.md` file.

As a quick start, you can run the following command from the project root:
```bash
docker-compose -f db/docker/docker-compose.yml up -d
```

### 2. Application Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/tarekbytes/aegis.git
    cd aegis
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate
    ```
    On Windows, use `venv\Scripts\activate`.

3.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## 🏃 Running the Application

Once the database is running and the dependencies are installed, you can start the FastAPI application using `uvicorn`:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
The `--reload` flag enables auto-reloading for development, so the server will restart after code changes.

The API will be available at `http://localhost:8000`, and the interactive documentation (Swagger UI) can be accessed at `http://localhost:8000/docs`.

## 🧪 Using the Mock OSV Server for Local Testing

For local development and testing, you can use the included `mock_osv` FastAPI service to simulate responses from osv.dev. This allows you to test vulnerability scanning without making real network calls.

**To run the mock OSV server:**
```bash
uvicorn mock_osv.main:app --reload --port 8001
```

**To point the main app to the mock server:**
Set the `OSV_API_URL` in your environment or configuration to:
```
http://localhost:8001/v1/querybatch
```
This will cause all vulnerability queries to go to your local mock server.

## 🧹 Code Quality: Ruff and Pre-commit Hooks

We use [Ruff](https://github.com/astral-sh/ruff) for fast Python linting and code quality checks, and [pre-commit](https://pre-commit.com/) to enforce these checks before every commit.

Our `.pre-commit-config.yaml` is configured to run Ruff on all staged Python files before each commit. This ensures code style and quality are maintained automatically.

**Example `.pre-commit-config.yaml`:**
```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.4
    hooks:
      - id: ruff
```

**To set up:**
1. Install ruff and pre-commit:
    ```bash
    pip install ruff pre-commit
    ```
2. Install the pre-commit hook:
    ```bash
    pre-commit install
    ```
Now, every time you commit, Ruff will automatically check your code for linting issues.

If you want to run Ruff manually on all files:
```bash
ruff .
```

## ✅ Running Tests and Checking Coverage

To validate the behavior of the application's components, you can run the automated test suite using `pytest` from the root of the project:

```bash
pytest
```

To check code coverage, run:
```bash
pytest --cov
```
This will display a coverage summary in the terminal. Aim for high coverage to ensure code reliability.
