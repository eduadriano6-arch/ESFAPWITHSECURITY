package pe.edu.esfap.portal;

import jakarta.persistence.*;
import java.time.Instant;

/** Registro de auditoría de seguridad (actor y acción se guardan cifrados). */
@Entity
public class LogEntry {
    @Id @GeneratedValue public Long id;
    public Instant at = Instant.now();
    @Convert(converter = CryptoConverter.class) @Column(length = 600) public String actor;
    @Convert(converter = CryptoConverter.class) @Column(length = 1000) public String action;
}
