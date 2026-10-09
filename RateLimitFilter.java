package pe.edu.esfap.portal;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Limita peticiones por IP (anti fuerza bruta / abuso) y rechaza cuerpos demasiado grandes. Responde 429 / 413. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class RateLimitFilter extends OncePerRequestFilter {
    private static final long MAX_BODY = 10_000_000L;
    private final ConcurrentHashMap<String, long[]> hits = new ConcurrentHashMap<>();

    private boolean allow(String key, int max, long windowMs) {
        long now = System.currentTimeMillis();
        if (hits.size() > 50_000) hits.entrySet().removeIf(e -> now - e.getValue()[0] > windowMs);
        long[] w = hits.compute(key, (k, v) -> {
            if (v == null || now - v[0] > windowMs) return new long[]{now, 1};
            v[1]++;
            return v;
        });
        return w[1] <= max;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest q, HttpServletResponse r, FilterChain c) throws ServletException, IOException {
        String uri = q.getRequestURI();
        if (uri.startsWith("/api/")) {
            // getRemoteAddr() ya refleja X-Forwarded-For solo si server.forward-headers-strategy lo permite (proxy de confianza)
            String ip = q.getRemoteAddr();
            boolean post = "POST".equals(q.getMethod());
            if (q.getContentLengthLong() > MAX_BODY) { r.setStatus(413); return; }
            boolean ok = allow("api:" + ip, 300, 60_000);
            if (ok && post && uri.equals("/api/login")) ok = allow("login:" + ip, 10, 600_000);
            if (ok && post && uri.equals("/api/password")) ok = allow("pw:" + ip, 10, 900_000);
            if (ok && uri.startsWith("/api/verify/")) ok = allow("verify:" + ip, 30, 60_000);
            if (!ok) { r.setHeader("Retry-After", "60"); r.setStatus(429); return; }
        }
        c.doFilter(q, r);
    }
}
