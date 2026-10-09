package pe.edu.esfap.portal;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.header.writers.StaticHeadersWriter;

/**
 * Cabeceras de seguridad, CSRF con token por sesión, HTTPS obligatorio (producción) y CSP estricta.
 * La autenticación y los roles los resuelve ApiController (sesión del servidor, cookie HttpOnly).
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final boolean requireHttps;

    SecurityConfig(@Value("${portal.require-https:false}") boolean requireHttps) { this.requireHttps = requireHttps; }

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        String csp = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; "
            + "script-src 'self'; style-src 'self' https://fonts.googleapis.com; style-src-attr 'unsafe-inline'; "
            + "img-src 'self' data: blob:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self'; "
            + "frame-src blob:; object-src 'self' blob:; manifest-src 'none'; worker-src 'none'; media-src 'none'"
            + (requireHttps ? "; upgrade-insecure-requests" : "");

        http
            .authorizeHttpRequests(a -> a.anyRequest().permitAll())
            .csrf(c -> c.csrfTokenRepository(new HttpSessionCsrfTokenRepository()).csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable)
            .requestCache(c -> c.disable())
            .headers(h -> h
                .contentSecurityPolicy(c -> c.policyDirectives(csp))
                .frameOptions(f -> f.deny())
                .httpStrictTransportSecurity(s -> s.includeSubDomains(true).maxAgeInSeconds(63072000).preload(true))
                .referrerPolicy(r -> r.policy(ReferrerPolicy.NO_REFERRER))
                .addHeaderWriter(new StaticHeadersWriter("Permissions-Policy",
                    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), interest-cohort=()"))
                .addHeaderWriter(new StaticHeadersWriter("Cross-Origin-Opener-Policy", "same-origin-allow-popups"))
                .addHeaderWriter(new StaticHeadersWriter("Cross-Origin-Resource-Policy", "same-origin"))
                .addHeaderWriter(new StaticHeadersWriter("X-Permitted-Cross-Domain-Policies", "none")));

        if (requireHttps) http.requiresChannel(c -> c.anyRequest().requiresSecure());
        return http.build();
    }
}
