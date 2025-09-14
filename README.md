# PickFolio Auth Service 🔐

The central service for all user identity and authentication operations in the PickFolio ecosystem. This service is the single source of truth for user accounts and is responsible for issuing secure access tokens that are consumed by all other services.

---

## Core Responsibilities

* **User Registration & Login**: Handles the creation and authentication of user accounts.
* **Token Issuance**: Generates secure, short-lived JWT access tokens and long-lived refresh tokens.
* **Session Management**: Manages user sessions across multiple devices via refresh tokens.
* **Public Key Exposure**: Exposes its public signing key via a standard JWKS endpoint (`/oauth2/jwks`), allowing other microservices to verify the authenticity of JWTs without needing access to the private key.

---

## Technology Stack

* **Framework**: Spring Boot 3
* **Language**: Java
* **Security**: Spring Security 6
* **Database**: PostgreSQL
* **ORM**: Spring Data JPA / Hibernate
* **Build Tool**: Gradle

---

## Local Development Setup

1.  **Clone the repository**:
    ```bash
    git clone <your-repo-url>
    cd pickfolio-auth-service
    ```
2.  **Setup the Database**:
    Connect to your PostgreSQL instance and create the database. The user credentials are in the properties file.
    ```sql
    CREATE DATABASE pickfolio_auth;
    ```
3.  **Configure `application.yml`**:
    Ensure the `src/main/resources/application.yml` file has the correct database credentials.
4.  **Run the application**:
    ```bash
    ./gradlew bootRun
    ```
    The service will start on `http://localhost:8080`.

---

## API Endpoints

All endpoints are prefixed with `/api/auth`.

| Method | Path | Description | Auth Required? |
| :--- | :--- | :--- | :--- |
| **POST** | `/register` | Creates a new user account. | No |
| **POST** | `/login` | Authenticates a user and returns access/refresh tokens. | No |
| **POST** | `/refresh` | Issues a new access token using a refresh token. | No |
| **POST** | `/logout` | Invalidates a single refresh token. | No |
| **POST** | `/logout-all`| Invalidates all refresh tokens for the current user. | Yes (Bearer) |

### Public Key Endpoint:

* **GET** `/oauth2/jwks`: Exposes the public signing key for other services to use for token validation.
