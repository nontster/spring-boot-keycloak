package com.n12g.demo.keycloak;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
public abstract class KeycloakTestContainers {

    @Container
    protected static final KeycloakContainer keycloakContainer = new KeycloakContainer()
            .withRealmImportFile("keycloak/myrealm-realm.json");

    @DynamicPropertySource
    static void registerResourceServerIssuerProperty(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> keycloakContainer.getAuthServerUrl() + "/realms/myrealm");
        registry.add("spring.security.oauth2.client.provider.keycloak.issuer-uri", () -> keycloakContainer.getAuthServerUrl() + "/realms/myrealm");
    }
}
