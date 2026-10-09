package pe.edu.esfap.portal;

import java.util.Set;

/** Reglas de seguridad puras (fáciles de probar): bloqueo, contraseñas, roles y nombres de usuario. */
public final class Policy {
    public static final int MAX_FAILS = 3;
    public static final int MIN_PASSWORD = 12;
    private static final String[] COMMON = {"password", "contrasena", "contraseña", "12345678", "qwerty", "esfap", "admin", "letmein", "abc123", "welcome"};
    private Policy() {}

    public static boolean locked(int fails) { return fails >= MAX_FAILS; }

    public static boolean strongPassword(String p) { return strongPassword(p, null); }

    /** Mínimo 12 caracteres, minúscula, mayúscula, número y símbolo; sin el usuario ni palabras muy comunes. */
    public static boolean strongPassword(String p, String username) {
        if (p == null || p.length() < MIN_PASSWORD || p.length() > 72) return false;
        if (!p.matches(".*[a-z].*") || !p.matches(".*[A-Z].*") || !p.matches(".*\\d.*") || !p.matches(".*[^A-Za-z0-9].*")) return false;
        String l = p.toLowerCase();
        if (username != null && username.length() >= 3 && l.contains(username.toLowerCase())) return false;
        for (String c : COMMON) if (l.contains(c)) return false;
        return true;
    }

    public static boolean validRole(String r) { return r != null && Set.of("est", "doc", "adm", "ti").contains(r); }
    public static boolean validUsername(String u) { return u != null && u.matches("[A-Za-z0-9._-]{3,30}"); }
    public static boolean canViewLogs(String r) { return "ti".equals(r) || "adm".equals(r); }
    public static boolean canManageUsers(String r) { return "ti".equals(r) || "adm".equals(r); }

    /** Evita escalada de privilegios: Soporte TI gestiona todos los roles; Administración solo estudiantes y docentes. */
    public static boolean canAssignRole(String actor, String target) {
        if (!validRole(target)) return false;
        if ("ti".equals(actor)) return true;
        return "adm".equals(actor) && ("est".equals(target) || "doc".equals(target));
    }
}
