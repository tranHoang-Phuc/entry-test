# Entry Test Project

This project is a microservices-based application built using Spring Boot. It consists of multiple services, including:

- **Identity Service**: Handles user authentication and authorization.
- **Profile Service**: Manages user profiles.
- **Notification Service**: Sends notifications to users.
- **API Gateway**: Acts as a single entry point for all services.

## Prerequisites

- Java 21
- Maven
- Docker and Docker Compose

## Getting Started

### 1. Clone the Repository
```bash
git clone <repository-url>
cd entry-test
```

### 2. Set Up Environment Variables

Ensure the `.env` file is properly configured. Below is an example of the required variables:

```dotenv
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_USER=admin
POSTGRES_PASSWORD=admin
POSTGRES_DB=identity-service
...
```

### 3. Build and Run Services

#### Using Docker Compose

1. Check out docker branch:
```bash
git checkout docker
```

2. Run the following command to start all services:
```bash
  docker compose -f docker-compose.yaml up -d --build 
```

#### Running Locally

1. Start the required dependencies (e.g., PostgreSQL, Redis, Kafka) using Docker Compose:
   ```bash
    docker compose -f docker-compose.yaml up -d --build 
   ```
2. Run project
   ```

### 4. Access the Application

- **API Gateway**: `http://localhost:9191`
- **Identity Service**: `http://localhost:8090/identity`
- **Profile Service**: `http://localhost:8081/user`
- **Notification Service**: `http://localhost:8082/notification`
- **SWAGGER UI**: `http://localhost:9191/swagger-ui`

## Project Structure

- **api-gateway**: Contains the API Gateway configuration and routes and swagger for all api.
- **identity-service**: Manages user authentication and authorization.
- **profile-service**: Handles user profile operations.
- **notification-service**: Sends email notifications.

## Technologies Used

- **Spring Boot**: Framework for building microservices.
- **PostgreSQL**: Database for storing data.
- **Redis**: In-memory data store for caching.
- **Kafka**: Message broker for asynchronous communication.
- **Docker**: Containerization platform.
- **Spring Cloud Gateway**: API Gateway for routing requests.
- **Spring Security**: Security framework for authentication and authorization.

## License

This project is licensed under the MIT License.
