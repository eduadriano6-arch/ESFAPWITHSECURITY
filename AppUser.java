package pe.edu.esfap.portal;

import jakarta.persistence.*;

/** Usuario del portal. La contraseña se guarda solo como hash BCrypt; el nombre se guarda cifrado (AES-GCM). */
@Entity @Table(name = "usuarios")
public class AppUser {
    @Id public String username;
    public String passwordHash;
    public String role;
    @Convert(converter = CryptoConverter.class) @Column(length = 600) public String name;
    public boolean active = true;
    public int fails;
}
