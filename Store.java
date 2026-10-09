package pe.edu.esfap.portal;

import jakarta.persistence.*;

/** Datos institucionales del portal (matrículas, pagos, notas, trámites, tickets) en JSON. */
@Entity
public class Store {
    @Id public Long id = 1L;
    @Lob public String json;
}
