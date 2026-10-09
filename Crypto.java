package pe.edu.esfap.portal;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cifrado autenticado AES-256-GCM para datos en reposo (estado institucional, nombres, auditoría).
 * Formato almacenado: "v1:" + Base64(IV[12] || texto cifrado || etiqueta GCM[16]). IV aleatorio por cada cifrado.
 * Clave: variable de entorno PORTAL_DATA_KEY (Base64 de 32 bytes: openssl rand -base64 32).
 * Sin variable: en desarrollo se genera ./data/portal.key; en producción (portal.require-key=true) el arranque falla.
 * Los valores sin prefijo "v1:" se tratan como texto heredado (migración transparente: se cifran al volver a guardarse).
 */
public final class Crypto {
    private static final String PREFIX = "v1:";
    private static final SecureRandom RNG = new SecureRandom();
    private static SecretKeySpec key;
    private static boolean required;

    private Crypto() {}

    static synchronized void require(boolean r) { required = r; key(); }

    /** Solo para pruebas. */
    static synchronized void setKey(byte[] k) { key = new SecretKeySpec(k, "AES"); }

    private static synchronized SecretKeySpec key() {
        if (key != null) return key;
        String env = System.getenv("PORTAL_DATA_KEY");
        try {
            if (env != null && !env.isBlank()) {
                byte[] k = Base64.getDecoder().decode(env.trim());
                if (k.length != 32) throw new IllegalStateException("PORTAL_DATA_KEY debe ser Base64 de 32 bytes (openssl rand -base64 32)");
                key = new SecretKeySpec(k, "AES");
                return key;
            }
            if (required) throw new IllegalStateException("Falta la variable de entorno PORTAL_DATA_KEY (obligatoria en producción)");
            Path f = Path.of("data", "portal.key");
            if (Files.exists(f)) {
                key = new SecretKeySpec(Base64.getDecoder().decode(Files.readString(f).trim()), "AES");
            } else {
                byte[] k = new byte[32];
                RNG.nextBytes(k);
                Files.createDirectories(f.getParent());
                Files.writeString(f, Base64.getEncoder().encodeToString(k));
                try { Files.setPosixFilePermissions(f, PosixFilePermissions.fromString("rw-------")); } catch (UnsupportedOperationException ignored) { /* Windows */ }
                key = new SecretKeySpec(k, "AES");
                System.err.println("[AVISO] Clave de cifrado de desarrollo creada en ./data/portal.key. En producción use PORTAL_DATA_KEY.");
            }
            return key;
        } catch (IOException e) {
            throw new IllegalStateException("No se pudo preparar la clave de cifrado", e);
        }
    }

    public static String encrypt(String plain) {
        if (plain == null) return null;
        try {
            byte[] iv = new byte[12];
            RNG.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key(), new GCMParameterSpec(128, iv));
            byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            ByteBuffer b = ByteBuffer.allocate(iv.length + ct.length);
            b.put(iv).put(ct);
            return PREFIX + Base64.getEncoder().encodeToString(b.array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Error de cifrado", e);
        }
    }

    public static String decrypt(String stored) {
        if (stored == null || !stored.startsWith(PREFIX)) return stored; // texto heredado sin cifrar
        try {
            byte[] all = Base64.getDecoder().decode(stored.substring(PREFIX.length()));
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, all, 0, 12));
            return new String(c.doFinal(all, 12, all.length - 12), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("Dato cifrado ilegible o alterado (clave incorrecta o manipulación)", e);
        }
    }
}
