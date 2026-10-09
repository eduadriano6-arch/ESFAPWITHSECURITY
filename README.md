# Portal ESFAP (prototipo) – Spring Boot

Importar en Spring Tool Suite: File > Import > Maven > Existing Maven Projects > carpeta `portal-esfap`.
Ejecutar: clic derecho en `PortalApplication` > Run As > Spring Boot App. Abrir http://localhost:8080
Pruebas: Run As > JUnit Test (o `mvn test`). Requiere JDK 17+.

Al primer arranque las contraseñas iniciales se generan al azar y se muestran **una sola vez en la consola**.
Para una demo local con contraseñas conocidas y cookie sin `Secure`: `-Dspring.profiles.active=dev`.
Producción: `-Dspring.profiles.active=prod` + variables `PORTAL_DATA_KEY`, `DB_FILE_PASSWORD`, `DB_USER_PASSWORD` (ver `docs/SEGURIDAD.md`).

Front: `src/main/resources/static/` (`index.html`, `app.js`, `app.css`; datos de prueba por defecto en memoria).
Los datos se guardan en `./data` (H2), cifrados. Más detalle en `docs/DOCUMENTACION.md` y `docs/SEGURIDAD.md`.
