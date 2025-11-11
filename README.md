# Repository for the Tilburg University "SWE for CySec" course group project, Group 1

## Project Structure

```
translation-system/
├── api-gateway/          # Single entry point and request router
├── auth-service/         # Handles user identity and JWTs
├── console-client/       # The command-line user interface
├── translation-service/  # Handles translation business logic
├── .gitignore
├── docker-compose.yml    # Orchestrates all backend services
└── README.md
```

The project uses a microservice architecture orchestrated by Docker Compose. While the services run inside Docker containers, we will also set up a local Python virtual environment for IDE integration, linting, and code completion.

## 1. Prerequisites

Before you begin, make sure you have the following software installed on your machine:

*   [Git](https://git-scm.com/downloads)
*   [Python](https://www.python.org/downloads/) (version 3.9 or higher)
*   [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) (Docker Desktop for Windows and Mac includes both).

## 2. Setup Steps

Follow these steps in your terminal to get the project running.

### Step 1: Clone the Repository

First, clone the project code from the Git repository.

```bash
git clone <your-repository-url>
cd translation-system
```

### Step 2: Create a Local Python Virtual Environment

```bash
# Create a virtual environment folder named .venv
python -m venv .venv

# Activate the virtual environment
# On Windows (Git Bash or PowerShell):
source .venv/Scripts/activate

# On macOS/Linux:
source .venv/bin/activate

# Install all dependencies from all services into this single environment
pip install -r api-gateway/requirements.txt
pip install -r auth-service/requirements.txt
pip install -r translation-service/requirements.txt
```
### Step 3: Build the Docker Images

This command reads the `Dockerfile` in each service's directory and builds the Docker images.

```bash
docker-compose build
```

### Step 4: Initialize the Databases (One-Time Setup)

Our services need their databases to be created and populated before they can run. We will run our custom `init-db` command for both the `auth-service` and `translation-service`.

```bash
# 1. Initialize the Authentication database and create the users
docker-compose run --rm auth-service flask init-db

# 2. Initialize the Translation database
docker-compose run --rm translation-service flask init-db
```
> **Note:** You only need to do this the very first time you set up the project or if you ever delete the database volumes.

### Step 5: Start All Services

This is the final step. The `up` command starts all the services defined in `docker-compose.yml`.

```bash
docker-compose up
```
You will see logs from all the services streaming in your terminal. The backend is now fully running!

To run the services in the background (detached mode), you can use:
```bash
docker-compose up -d
```

## 3. Development Workflow

*   **Making Code Changes**: Because we use Docker volumes, any changes you save in your local code editor will be automatically reflected inside the running containers. The Flask development servers will detect the changes and reload, so you don't need to rebuild or restart for most code changes.

*   **Viewing Logs**: To view the logs for a specific service, open a new terminal and use:
    ```bash
    # Tail the logs for the auth-service in real-time
    docker-compose logs -f auth-service

    # Tail the logs for the API gateway
    docker-compose logs -f api-gateway
    ```

*   **Stopping the Environment**: To stop all the services, press `Ctrl+C` in the terminal where `docker-compose up` is running. If you are in detached mode, use:
    ```bash
    docker-compose down
    ```
    > To stop the services and delete the database data, use `docker-compose down -v`.

## 4. Testing the API

You can test that everything is working using a tool like `curl`.

#### 1. Get a Token
```bash
curl -X POST -H "Content-Type: application/json" -d '{"username": "Nikola", "password": "password123"}' http://localhost:5000/login
```
This will return an `access_token`. Copy the token string.

#### 2. Use the Token
Replace `<YOUR_JWT_TOKEN>` with the token you just copied.
```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <YOUR_JWT_TOKEN>" -d '{"text": "My setup is working!"}' http://localhost:5000/translate
```
