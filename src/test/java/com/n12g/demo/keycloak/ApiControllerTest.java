package com.n12g.demo.keycloak;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class ApiControllerTest extends KeycloakTestContainers {

    @Autowired
    private WebTestClient webTestClient;

    @Autowired
    private ObjectMapper objectMapper;

    private String getAdminToken() {
        return getToken("admin", "admin");
    }

    private String getUserToken() {
        return getToken("user", "user");
    }

    private String getToken(String username, String password) {
        var tokenUrl = keycloakContainer.getAuthServerUrl() + "/realms/myrealm/protocol/openid-connect/token";
        var webClient = WebClient.builder().build();
        var response = webClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("grant_type", "password")
                        .with("client_id", "mywebapp")
                        .with("client_secret", "Y1qpv8u6YtcAP8CAANyYbhU9bipuARn9")
                        .with("username", username)
                        .with("password", password))
                .retrieve()
                .bodyToMono(Map.class)
                .block();
        return (String) response.get("access_token");
    }

    @Test
    void adminEndpointShouldReturnOkForAdmin() {
        webTestClient.get().uri("/api/admin")
                .headers(headers -> headers.setBearerAuth(getAdminToken()))
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void adminEndpointShouldReturnForbiddenForUser() {
        webTestClient.get().uri("/api/admin")
                .headers(headers -> headers.setBearerAuth(getUserToken()))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void userEndpointShouldReturnOkForUser() {
        webTestClient.get().uri("/api/users")
                .headers(headers -> headers.setBearerAuth(getUserToken()))
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void userEndpointShouldReturnOkForAdmin() {
        webTestClient.get().uri("/api/users")
                .headers(headers -> headers.setBearerAuth(getAdminToken()))
                .exchange()
                .expectStatus().isOk();
    }
}
