package kakha.kudava.filedrivespring.config;

import jakarta.servlet.DispatcherType;
import kakha.kudava.filedrivespring.repository.UserRepository;
import kakha.kudava.filedrivespring.services.objects.RootFolderService;
import kakha.kudava.filedrivespring.services.users.DbUserDetailsService;
import kakha.kudava.filedrivespring.services.jwt.JwtFilter;
import kakha.kudava.filedrivespring.services.jwt.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${ADMIN_PASSWORD}")
    private String ADMIN_PASSWORD;

    @Value("${app.cors.allowed-origins}")
    private List<String> allowedOrigins;

    @Bean
    public SecurityFilterChain apiSecurityFilterChain(
            HttpSecurity http,
            JwtService jwtService,
            DbUserDetailsService userDetailService
    ) throws Exception {

        http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .headers(headers ->
                        headers.frameOptions(frame -> frame.sameOrigin())
                )
                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS
                        )
                )
                .authorizeHttpRequests(auth -> auth

                        // StreamingResponseBody uses an asynchronous servlet dispatch.
                        // Authorization was already performed on the original request.
                        .dispatcherTypeMatchers(
                                DispatcherType.ASYNC,
                                DispatcherType.ERROR
                        ).permitAll()

                        .requestMatchers(
                                HttpMethod.OPTIONS,
                                "/**"
                        ).permitAll()

                        .requestMatchers(
                                "/h2-console/**"
                        ).permitAll()

                        .requestMatchers(
                                "/api/auth/login",
                                "/api/auth/logout",
                                "/api/auth/me",
                                "/api/auth/refresh"
                        ).permitAll()

                        .requestMatchers(
                                "/api/files",
                                "/api/files/**"
                        ).hasAnyRole("USER", "ADMIN")

                        .requestMatchers(
                                "/api/folders/**"
                        ).hasAnyRole("USER", "ADMIN")

                        .requestMatchers(
                                "/api/download/**"
                        ).hasAnyRole("USER", "ADMIN")

                        .requestMatchers(
                                "/api/quarantine/**"
                        ).hasRole("ADMIN")

                        .requestMatchers(
                                "/api/users/search"
                        ).hasAnyRole("USER", "ADMIN")

                        .requestMatchers(
                                "/api/users",
                                "/api/users/**"
                        ).hasRole("ADMIN")

                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/register"
                        ).permitAll()

                        .requestMatchers(
                                "/api/register/**"
                        ).hasRole("ADMIN")

                        .anyRequest().authenticated()
                );

        http.addFilterBefore(
                new JwtFilter(
                        jwtService,
                        userDetailService
                ),
                UsernamePasswordAuthenticationFilter.class
        );

        return http.build();
    }
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        config.setExposedHeaders(List.of("Authorization"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }

    @Bean
    CommandLineRunner createAdmin(UserRepository userRepository, PasswordEncoder passwordEncoder,
                                  RootFolderService rootFolderService) {
        return args -> {
            if (userRepository.findByUsername("admin").isEmpty()) {
                kakha.kudava.filedrivespring.model.User admin = new kakha.kudava.filedrivespring.model.User();
                admin.setUsername("admin");
                admin.setPassword(passwordEncoder.encode(ADMIN_PASSWORD));
                admin.setRole(kakha.kudava.filedrivespring.model.User.Role.ADMIN);
                userRepository.save(admin);
                rootFolderService.ensureRootFolder(admin);
            }
        };
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
