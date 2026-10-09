package pe.edu.esfap.portal;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/** Cifra/descifra columnas de texto en la base de datos con {@link Crypto}. */
@Converter
public class CryptoConverter implements AttributeConverter<String, String> {
    @Override public String convertToDatabaseColumn(String attribute) { return Crypto.encrypt(attribute); }
    @Override public String convertToEntityAttribute(String dbData) { return Crypto.decrypt(dbData); }
}
