# Seguridad del Portal ESFAP

## 1. Qué se protege y cómo

| Amenaza | Medida | Dónde |
|---|---|---|
| Robo de la cookie de sesión vía XSS | Cookie `__Host-ESFAPSESSION`: **HttpOnly** (JavaScript no puede leerla), **Secure**, **SameSite=Strict**, sin `Domain`, valor opaco aleatorio | `application.properties` |
| Secuestro / fijación de sesión | ID de sesión rotado al iniciar sesión y al cambiar contraseña; caduca a los 5 min de inactividad y a las 8 h absolutas; se invalida si cambia el `User-Agent` | `ApiController.me/login` |
| XSS | CSP estricta: `default-src 'none'; script-src 'self'` (sin scripts inline ni `eval`), salida escapada, el servidor rechaza `<` y `>` en los datos, solo PDF reales (`%PDF`) | `SecurityConfig`, `StateGuard`, `app.js` |
| CSRF | Token por sesión en cabecera `X-CSRF-TOKEN` + SameSite=Strict | `SecurityConfig`, `app.js (api)` |
| Fuerza bruta | Bloqueo a los 3 fallos; límite por IP (login 10/10 min, contraseña 10/15 min, API 300/min); BCrypt costo 12; igualación de tiempos si el usuario no existe | `RateLimitFilter`, `ApiController` |
| Acceso indebido a datos | Autorización por rol en el servidor: cada rol lee/escribe solo sus claves; el estudiante ve solo sus trámites y no puede emitir documentos, poner códigos, aprobar su matrícula ni cambiar importes | `StateGuard` |
| Escalada de privilegios | Administración no crea ni desactiva cuentas TI/Administración | `Policy.canAssignRole` |
| Datos legibles en disco | AES-256-GCM (IV aleatorio, detecta manipulación) para estado, nombres y auditoría + H2 con `CIPHER=AES` en producción | `Crypto`, `CryptoConverter` |
| Datos legibles en el navegador | El portal **no usa** `localStorage`, `sessionStorage` ni cookies propias; se purgan restos al cargar. Los datos viven solo en memoria y en el servidor | `app.js` |
| Clickjacking, sniffing, filtrado de referer, APIs del navegador | `frame-ancestors 'none'`, `X-Frame-Options`, `nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, COOP/CORP, HSTS (2 años) | `SecurityConfig` |
| Falsificación de certificados | Código de verificación generado con `crypto.getRandomValues`, formato validado y solo documentos «Emitido» | `app.js`, `ApiController.verify` |
| Fugas por errores | Sin trazas ni mensajes internos en errores, sin cabecera `Server`, sin consola H2, sin puerto TCP (`AUTO_SERVER` eliminado) | `application.properties` |
| Credenciales por defecto | Contraseñas iniciales aleatorias, mostradas una vez | `DataSeeder` |

## 2. Sobre las cookies y el almacenamiento (qué se puede y qué no)

* **Nadie puede ocultar una cookie al dueño de su propio navegador**: en las herramientas de desarrollo siempre se verá que existe. `HttpOnly` garantiza que ningún *script* (ni uno inyectado) pueda leerla ni enviarla a un atacante, y el valor es un identificador aleatorio sin información (todo lo demás está en el servidor).
* Cifrar datos dentro de `localStorage` con una clave que también está en el navegador solo da una falsa sensación de seguridad. La solución correcta, aplicada aquí, es **no guardar nada en el navegador** y cifrar en el servidor.

## 3. Puesta en producción (obligatorio)

1. HTTPS con TLS 1.2+ (proxy inverso Nginx/Caddy/Traefik) y perfil `prod`. El proxy debe enviar `X-Forwarded-For` y `X-Forwarded-Proto`; Tomcat los procesa solo desde proxies internos (`server.forward-headers-strategy=native`).
2. Variables de entorno (nunca en el repositorio):
   * `PORTAL_DATA_KEY`: `openssl rand -base64 32`
   * `DB_FILE_PASSWORD`, `DB_USER_PASSWORD`: contraseñas largas distintas para el cifrado del archivo H2 y para el usuario `sa`.
   * `PORTAL_BIND=0.0.0.0` solo si el proceso queda detrás del proxy (por defecto escucha en 127.0.0.1).
3. **Respalde `PORTAL_DATA_KEY` en un gestor de secretos**: sin ella los datos no se pueden descifrar.
4. Si ya existe `./data/esfap.mv.db` de una versión anterior: el perfil `prod` usa `./data/esfap-enc` (base nueva cifrada). Los datos antiguos en texto plano se cifran la próxima vez que se guardan. Las cuentas ya existentes **conservan sus contraseñas antiguas: cámbielas** (la nueva política exige 12+ caracteres).
5. Use `mvn org.owasp:dependency-check-maven:check` periódicamente y mantenga Spring Boot actualizado.

## 4. Lo que queda fuera de este alcance (honestidad técnica)

* No existe «seguridad 10/10»: este conjunto cubre OWASP Top 10 a nivel de aplicación, pero se recomienda una **prueba de penetración independiente** antes de operar con datos reales.
* **Modelo de datos del prototipo**: matrícula, pagos y tickets son un único registro compartido (demo de un estudiante). `StateGuard` impide que un rol toque lo que no le corresponde, pero no separa a un estudiante de otro. La solución real es la «siguiente etapa» del README: tablas JPA por estudiante (con `owner = usuario de la sesión` verificado en el servidor).
* **Pagos**: la pasarela es simulada; en producción el estado «Pagado» debe fijarlo el *webhook* firmado de la pasarela, no el cliente.
* **Doble factor (2FA/TOTP)** para Administración y Soporte TI: muy recomendable, no incluido.
* Código 423 (cuenta bloqueada) revela que la cuenta existe: se mantiene por usabilidad y está acotado por el límite por IP.
* Google Fonts es un recurso de terceros permitido en la CSP; para eliminarlo, aloje las fuentes en `static/`.
* El lector de PDF usa un `<iframe>` con URL `blob:`; la CSP lo permite (`frame-src blob:`, `object-src blob:`). Pruébelo en su navegador tras desplegar.
* Ley N.° 29733 (datos personales): inscribir el banco de datos, política de privacidad visible, atender derechos ARCO y notificar incidentes; son obligaciones organizativas además de técnicas.
