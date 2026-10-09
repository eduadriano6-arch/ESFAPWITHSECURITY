package pe.edu.esfap.portal;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Carga la clave de cifrado al arrancar (falla rápido si falta en producción). */
@Component
class CryptoInit {
    CryptoInit(@Value("${portal.require-key:false}") boolean required) { Crypto.require(required); }
}
