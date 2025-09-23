package com.n12g.demo.keycloak;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * This is the main class of the application.
 * It is a standard Spring Boot application class.
 */
@SpringBootApplication
public class KeycloakApplication {

	/**
	 * The main method of the application.
	 * @param args The command line arguments.
	 */
	public static void main(String[] args) {
		SpringApplication.run(KeycloakApplication.class, args);
	}

}