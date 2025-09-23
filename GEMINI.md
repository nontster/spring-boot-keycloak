# GEMINI.md

## Project Overview

This is a Spring Boot project that demonstrates how to integrate with Keycloak for authentication and authorization. The project is a web application with both a traditional UI and a REST API.

**Key Technologies:**

*   **Java 17**
*   **Spring Boot 3**
*   **Spring Security 6**
*   **OAuth 2.0 & OpenID Connect**
*   **Keycloak**
*   **Maven**
*   **Thymeleaf**

**Architecture:**

The application has two main parts:

1.  **Web UI:**
    *   Uses Spring Security's OAuth2 login for authentication against a Keycloak server.
    *   The UI is built with Thymeleaf.
    *   There are public pages (e.g., the home page) and protected pages (e.g., a user profile page).
    *   It uses a custom `OidcUserService` to map authorities from the OIDC user.

2.  **REST API:**
    *   Secured with JWT-based authentication.
    *   The API has endpoints that require different roles (e.g., `USER` and `ADMIN`).
    *   It uses a custom `JwtAuthConverter` to extract roles from the JWT.

## Building and Running

### Prerequisites

*   Java 17
*   Maven
*   A running Keycloak instance on `localhost:8180` with a realm named `myrealm`.

### Running the Application

1.  **Build the project:**

    ```bash
    ./mvnw clean install
    ```

2.  **Run the application:**

    ```bash
    ./mvnw spring-boot:run
    ```

The application will be available at `http://localhost:8080`.

### Keycloak Configuration

The application is configured to work with a Keycloak instance with the following settings:

*   **Issuer URI:** `http://localhost:8180/realms/myrealm`
*   **Client ID:** `mywebapp`
*   **Client Secret:** `Y1qpv8u6YtcAP8CAANyYbhU9bipuARn9`
*   **Authorization Grant Type:** `authorization_code`
*   **Redirect URI:** `{baseUrl}/login/oauth2/code/{registrationId}`
*   **Scope:** `openid, profile, email, roles`

## Development Conventions

*   **Coding Style:** The code follows standard Java conventions.
*   **Testing:** The project includes a basic test class `KeycloakApplicationTests.java`.
*   **Dependencies:** Dependencies are managed with Maven.
