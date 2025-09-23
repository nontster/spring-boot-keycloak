package com.n12g.demo.keycloak;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * This is the main class of the application.
 * It is a standard Spring Boot application class.
 */
@SpringBootApplication
public class KeycloakApplication {
	private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakApplication.class);

	/**
	 * The main method of the application.
	 * @param args The command line arguments.
	 */
	public static void main(String[] args) {
		SpringApplication.run(KeycloakApplication.class, args);
		LOGGER.info("Keycloak application has started successfully.");
	}

}