package pe.edu.esfap.portal;

import java.security.SecureRandom;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Crea los 4 usuarios iniciales la primera vez.
 * Por defecto genera contraseñas ALEATORIAS y las muestra una sola vez en la consola.
 * Con el perfil "dev" (portal.seed.demo-passwords=true) usa las contraseñas de demostración de la documentación.
 */
@Component
public class DataSeeder implements CommandLineRunner {
    private static final SecureRandom RNG = new SecureRandom();
    private static final String ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!#$%&*+-=?@";
    private final UserRepo users;
    private final boolean demo;

    DataSeeder(UserRepo u, @Value("${portal.seed.demo-passwords:false}") boolean demo) { users = u; this.demo = demo; }

    static String randomPassword(String username) {
        while (true) {
            char[] c = new char[16];
            for (int i = 0; i < c.length; i++) c[i] = ALPHABET.charAt(RNG.nextInt(ALPHABET.length()));
            String p = new String(c);
            if (Policy.strongPassword(p, username)) return p;
        }
    }

    public void run(String... args) {
        if (users.count() > 0) return;
        var enc = new BCryptPasswordEncoder(12);
        String[][] d = {{"E2024001", "Lucía Quispe Huamán", "est", "Estud2026"}, {"45678912", "Prof. Carlos Ccente", "doc", "Docen2026"},
            {"secretaria", "Rosa Palomino (Administración)", "adm", "Admin2026"}, {"soporte", "Soporte TI", "ti", "Soporte2026"}};
        var out = new StringBuilder();
        for (var r : d) {
            String pw = demo ? r[3] : randomPassword(r[0]);
            var u = new AppUser(); u.username = r[0]; u.name = r[1]; u.role = r[2]; u.passwordHash = enc.encode(pw); users.save(u);
            if (!demo) out.append(String.format("  %-10s  %s%n", r[0], pw));
        }
        if (!demo) System.out.println("\n=== CREDENCIALES INICIALES (se muestran UNA sola vez: guárdelas y cámbielas al ingresar) ===\n" + out
            + "==========================================================================================\n");
    }
}
