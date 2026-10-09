package pe.edu.esfap.portal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.*;

/** API REST: autenticación, sesión, datos institucionales (con autorización por rol), usuarios, auditoría y verificación. */
@RestController @RequestMapping("/api")
public class ApiController {
    record Login(String id, String pw) {}
    record Pass(String old, String neu) {}
    record NewUser(String username, String name, String role, String pw) {}

    private static final long ABSOLUTE_SESSION_MS = 8L * 60 * 60 * 1000; // la sesión nunca dura más de 8 h
    private static final int MAX_STATE_CHARS = 8_000_000;

    private final UserRepo users; private final StoreRepo store; private final LogRepo logs;
    private final BCryptPasswordEncoder enc = new BCryptPasswordEncoder(12);
    private final String dummyHash = enc.encode("contraseña-ficticia-para-igualar-tiempos");
    private final ObjectMapper om = new ObjectMapper();
    private final Object stateLock = new Object();

    public ApiController(UserRepo u, StoreRepo s, LogRepo l) { users = u; store = s; logs = l; }

    static String safe(String s) {
        if (s == null) return "?";
        String c = s.replaceAll("[^A-Za-z0-9._@ -]", "_");
        return c.length() > 60 ? c.substring(0, 60) : c;
    }

    void audit(String who, String what) {
        var e = new LogEntry();
        e.actor = safe(who);
        e.action = what.length() > 300 ? what.substring(0, 300) : what;
        logs.save(e);
    }

    static String uaHash(HttpServletRequest q) {
        try {
            String ua = q.getHeader("User-Agent");
            return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest((ua == null ? "" : ua).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    /** Usuario de la sesión actual, o null. Valida vigencia absoluta, huella del navegador y que la cuenta siga activa. */
    AppUser me(HttpServletRequest q) {
        HttpSession s = q.getSession(false);
        if (s == null) return null;
        Object id = s.getAttribute("u");
        Object t0 = s.getAttribute("t0");
        if (!(id instanceof String uid) || !(t0 instanceof Long start)) return null;
        if (System.currentTimeMillis() - start > ABSOLUTE_SESSION_MS) { s.invalidate(); return null; }
        if (!uaHash(q).equals(s.getAttribute("ua"))) {
            audit(uid, "Sesión invalidada: el navegador no coincide con el de inicio de sesión");
            s.invalidate();
            return null;
        }
        return users.findById(uid).filter(x -> x.active && !Policy.locked(x.fails)).orElse(null);
    }

    Map<String, Object> view(AppUser u) { return Map.of("id", u.username, "role", u.role, "name", u.name); }

    /** Token CSRF de la sesión (se envía en la cabecera X-CSRF-TOKEN en cada petición que modifica datos). */
    @GetMapping("/csrf")
    Map<String, String> csrf(HttpServletRequest q) {
        var t = (CsrfToken) q.getAttribute(CsrfToken.class.getName());
        if (t == null) throw new IllegalStateException("CSRF no disponible");
        return Map.of("header", t.getHeaderName(), "token", t.getToken());
    }

    @PostMapping("/login")
    ResponseEntity<?> login(@RequestBody Login b, HttpServletRequest q) {
        var id = (b == null || b.id() == null) ? "" : b.id().trim();
        var pw = (b == null || b.pw() == null) ? "" : b.pw();
        String ip = q.getRemoteAddr();
        AppUser u = (id.isEmpty() || id.length() > 60) ? null : users.findById(id).orElse(null);
        if (u == null) {
            enc.matches(pw.length() > 72 ? "x" : pw, dummyHash); // igualar tiempos: no revela si el usuario existe
            audit(id, "Login fallido: usuario inexistente [" + ip + "]");
            return ResponseEntity.status(401).build();
        }
        if (Policy.locked(u.fails) || !u.active) {
            enc.matches("x", dummyHash);
            audit(u.username, "Login rechazado: cuenta bloqueada o inactiva [" + ip + "]");
            return ResponseEntity.status(423).build();
        }
        if (pw.length() > 72 || !enc.matches(pw, u.passwordHash)) {
            u.fails++; users.save(u);
            audit(u.username, "Login fallido (" + u.fails + ") [" + ip + "]");
            return ResponseEntity.status(401).build();
        }
        u.fails = 0; users.save(u);
        HttpSession s = q.getSession(true);
        q.changeSessionId(); // anti fijación de sesión
        s.removeAttribute(HttpSessionCsrfTokenRepository.class.getName() + ".CSRF_TOKEN"); // rota el token CSRF
        s.setAttribute("u", u.username);
        s.setAttribute("t0", System.currentTimeMillis());
        s.setAttribute("ua", uaHash(q));
        s.setMaxInactiveInterval(300);
        audit(u.username, "Inicio de sesión [" + ip + "]");
        return ResponseEntity.ok(view(u));
    }

    @PostMapping("/logout")
    ResponseEntity<?> logout(HttpServletRequest q) {
        var u = me(q); if (u != null) audit(u.username, "Cierre de sesión");
        var s = q.getSession(false); if (s != null) s.invalidate();
        return ResponseEntity.ok().build();
    }

    @GetMapping("/me")
    ResponseEntity<?> whoami(HttpServletRequest q) { var u = me(q); return u == null ? ResponseEntity.status(401).build() : ResponseEntity.ok(view(u)); }

    JsonNode loadState() {
        try {
            String raw = store.findById(1L).map(x -> Crypto.decrypt(x.json)).orElse(null);
            return (raw == null || raw.isBlank()) ? om.createObjectNode() : om.readTree(raw);
        } catch (Exception e) {
            return om.createObjectNode();
        }
    }

    @GetMapping(value = "/state", produces = "application/json")
    ResponseEntity<String> getState(HttpServletRequest q) {
        var u = me(q);
        if (u == null) return ResponseEntity.status(401).build();
        return ResponseEntity.ok(StateGuard.readView(u.role, u.username, loadState()).toString());
    }

    @PutMapping("/state")
    ResponseEntity<?> putState(@RequestBody String json, HttpServletRequest q) {
        var u = me(q);
        if (u == null) return ResponseEntity.status(401).build();
        if (json == null || json.length() > MAX_STATE_CHARS) return ResponseEntity.status(413).build();
        synchronized (stateLock) {
            try {
                var merged = StateGuard.mergeWrite(u.role, u.username, loadState(), om.readTree(json));
                var s = new Store();
                s.json = Crypto.encrypt(merged.toString()); // el estado se guarda cifrado (AES-256-GCM)
                store.save(s);
            } catch (IllegalArgumentException e) {
                audit(u.username, "Estado rechazado: " + safe(e.getMessage()));
                return ResponseEntity.badRequest().build();
            } catch (Exception e) {
                return ResponseEntity.badRequest().build();
            }
        }
        return ResponseEntity.ok().build();
    }

    @PostMapping("/password")
    ResponseEntity<?> password(@RequestBody Pass b, HttpServletRequest q) {
        var u = me(q); if (u == null) return ResponseEntity.status(401).build();
        if (b.old() == null || b.neu() == null || b.old().length() > 72 || b.neu().equals(b.old())
            || !enc.matches(b.old(), u.passwordHash) || !Policy.strongPassword(b.neu(), u.username)) return ResponseEntity.badRequest().build();
        u.passwordHash = enc.encode(b.neu()); users.save(u);
        q.changeSessionId();
        audit(u.username, "Cambio de contraseña");
        return ResponseEntity.ok().build();
    }

    @GetMapping("/logs")
    ResponseEntity<?> logs(HttpServletRequest q) {
        var u = me(q); if (u == null || !Policy.canViewLogs(u.role)) return ResponseEntity.status(403).build();
        return ResponseEntity.ok(logs.findTop100ByOrderByIdDesc());
    }

    @GetMapping("/users")
    ResponseEntity<?> listUsers(HttpServletRequest q) {
        var u = me(q); if (u == null || !Policy.canManageUsers(u.role)) return ResponseEntity.status(403).build();
        return ResponseEntity.ok(users.findAll().stream().map(x -> Map.of("username", x.username, "name", x.name, "role", x.role, "active", x.active, "fails", x.fails)).toList());
    }

    @PostMapping("/users")
    ResponseEntity<?> addUser(@RequestBody NewUser b, HttpServletRequest q) {
        var u = me(q); if (u == null || !Policy.canManageUsers(u.role)) return ResponseEntity.status(403).build();
        if (!Policy.validUsername(b.username()) || !Policy.canAssignRole(u.role, b.role()) || b.name() == null || b.name().isBlank() || b.name().length() > 100
            || b.name().matches(".*[<>].*") || !Policy.strongPassword(b.pw(), b.username()) || users.existsById(b.username())) return ResponseEntity.badRequest().build();
        var n = new AppUser(); n.username = b.username(); n.name = b.name().trim(); n.role = b.role(); n.passwordHash = enc.encode(b.pw());
        users.save(n); audit(u.username, "Usuario creado: " + n.username + " (" + n.role + ")");
        return ResponseEntity.ok().build();
    }

    @PutMapping("/users/{id}/toggle")
    ResponseEntity<?> toggle(@PathVariable String id, HttpServletRequest q) {
        var u = me(q); if (u == null || !Policy.canManageUsers(u.role)) return ResponseEntity.status(403).build();
        var t = id.length() > 60 ? null : users.findById(id).orElse(null);
        if (t == null || t.username.equals(u.username)) return ResponseEntity.badRequest().build();
        if (!Policy.canAssignRole(u.role, t.role)) return ResponseEntity.status(403).build();
        t.active = !t.active; t.fails = 0; users.save(t); audit(u.username, (t.active ? "Usuario activado: " : "Usuario desactivado: ") + t.username);
        return ResponseEntity.ok().build();
    }

    /** Verificación pública de autenticidad por código del documento (solo documentos emitidos). */
    @GetMapping("/verify/{code}")
    Map<String, Object> verify(@PathVariable String code) {
        if (code == null || !code.matches("ESFAP-[A-Z0-9]{6}")) return Map.of("valid", false);
        try {
            for (var t : loadState().path("tram"))
                if (code.equals(t.path("code").asText()) && "Emitido".equals(t.path("st").asText()))
                    return Map.of("valid", true, "tipo", t.path("t").asText(), "estado", t.path("st").asText());
        } catch (Exception e) { /* se responde como no válido */ }
        return Map.of("valid", false);
    }
}
