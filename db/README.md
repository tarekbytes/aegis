# Aegis Database Setup

This document provides instructions for setting up the local PostgreSQL database for the Aegis project using Docker.

## Prerequisites

- [Docker](https://www.docker.com/get-started) must be installed and running on your system.

## Local Setup Instructions

The project uses Docker Compose to manage the PostgreSQL database service. The configuration is located in the `db/docker/docker-compose.yml` file.

To start the database for the first time:

1.  Navigate to the root directory of the project (`aegis`).
2.  Run the following command in your terminal:

    ```bash
    docker-compose -f db/docker/docker-compose.yml up -d
    ```

This command will:
- Pull the `postgres:15-alpine` image from Docker Hub.
- Create a new container named `aegis-db`.
- Create a database named `aegis` with a user `aegis_user` and password `devpassword`.
- Execute the `db/init.sql` script to create the necessary tables.
- Store the database data in a persistent Docker volume named `postgres_data`.
- Map port `5432` on your local machine to the container's port `5432`.

## Managing the Database

- **To stop the database container:**
  ```bash
  docker-compose -f db/docker/docker-compose.yml down
  ```

- **To view the container logs:**
  ```bash
  docker-compose -f db/docker/docker-compose.yml logs -f
  ```

## Database Credentials (Local)

- **Username:** `aegis_user`
- **Password:** `devpassword`
- **Database Name:** `aegis`
- **Host:** `localhost`
- **Port:** `5432` 

## Troubleshooting

### Port Conflicts

If you encounter an error indicating that port `5432` is already allocated, it means another service (likely another PostgreSQL instance) is using that port. To resolve this, you can change the host port mapping in the `db/docker/docker-compose.yml` file.

For example, to use port `5433` on your host machine, change the `ports` section as follows:

```diff
-      - "5432:5432"
+      - "5433:5432"
```

After making this change, you will connect to the database using the new port (`5433` in this example).
