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
│   │   └── project.py       # Pydantic models
│   ├── routers/
│   │   └── projects.py      # Project-related API routes
│   └── main.py              # Main FastAPI application
├── db/
│   ├── docker/
│   │   └── docker-compose.yml # Docker Compose for the database
│   ├── README.md            # Database setup instructions
│   └── init.sql             # PostgreSQL schema initialization
├── tests/
│   └── test_projects.py     # Unit tests for the projects router
└── requirements.txt         # Python dependencies
```

## 🚀 Getting Started

Follow these instructions to get the project up and running on your local machine for development and testing purposes.

### Prerequisites

*   Python 3.11+
*   Docker and Docker Compose
*   A Python virtual environment tool (e.g., `venv`)

### 1. Database Setup

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

## ✅ Running Tests

To validate the behavior of the application's components, you can run the automated test suite using `pytest` from the root of the project:

```bash
pytest
```

This will discover and run all the tests in the `tests/` directory.
