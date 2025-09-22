package com.n12g.demo.keycloak;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // ✅ 2. Inject ค่า clientId จาก application.yml
    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String keycloakClientId;

    // ✅ 3. Inject ClientRegistrationRepository เข้ามา
    private final ClientRegistrationRepository clientRegistrationRepository;

    public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    // ✅ 4. สร้าง OIDC Logout Handler
    private OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);
        successHandler.setPostLogoutRedirectUri("{baseUrl}");
        return successHandler;
    }

    // 1. สร้าง Bean สำหรับ JwtAuthenticationConverter (เหมือนเดิม)
    //private JwtAuthenticationConverter jwtAuthenticationConverter() {
    //    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        // บอกให้ Converter ใช้ KeycloakRoleConverter ของเราในการแปลง Roles
    //    converter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());
    //    return converter;
    //}

    // ✅ 3. แก้ไขการสร้าง Bean ของ JwtAuthenticationConverter
    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        // ส่ง clientId เข้าไปใน constructor
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter(keycloakClientId));
        return converter;
    }

    // ✅ 4. แก้ไขการสร้าง Bean ของ oidcUserAuthorityMapper
    @Bean
    public GrantedAuthoritiesMapper oidcUserAuthorityMapper() {
        // ส่ง clientId เข้าไปใน constructor
        return new OidcUserAuthorityMapper(keycloakClientId);
    }

    // 2. สร้าง SecurityFilterChain สำหรับ API (Resource Server)
    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // ✅  <-- จุดที่แก้ไข
                // ใช้ .securityMatcher() แบบใหม่ แทน new AntPathRequestMatcher()
                .securityMatcher("/api/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/user/**").hasRole("USER")
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt
                        .jwtAuthenticationConverter(jwtAuthenticationConverter()))
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable());

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // สำหรับ FilterChain ที่สอง เราไม่จำเป็นต้องใส่ securityMatcher()
                // เพราะมันจะทำงานกับ Request ทั้งหมดที่ "ไม่ตรง" กับ Chain ที่มี Order สูงกว่า
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/").permitAll()
                        //.requestMatchers("/profile").hasAnyRole("USER", "ADMIN") // หน้า /profile ต้องมี Role USER หรือ ADMIN
                        .anyRequest().authenticated()
                )
                .oauth2Login(Customizer.withDefaults()) // ใช้ Customizer.withDefaults() สำหรับการตั้งค่าพื้นฐาน
                .logout(logout -> logout
                        // ✅ 5. กำหนดให้ใช้ OIDC Logout Handler ของเรา
                        .logoutSuccessHandler(oidcLogoutSuccessHandler())
                );

        return http.build();
    }
}
