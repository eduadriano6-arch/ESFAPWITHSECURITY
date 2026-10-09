# Portal ESFAP – Documentación técnica

## Arquitectura
Navegador (HTML/JS) -> Spring Boot (API REST + estáticos) -> base de datos. Modelo híbrido: portal y BD del portal en la nube; BD institucional en la VLAN 20 de la sede (accesible solo en red local). Respaldo: copia cifrada de `./data/esfap.mv.db` a la sede.

## Modelo de datos
- `usuarios`(username PK, password_hash BCrypt, role, name, active, fails)
- `store`(id PK, json CLOB): matrículas, pagos, notas, trámites, tickets, biblioteca
- `log_entry`(id PK, at, actor, action): auditoría

## Seguridad
Resumen (detalle completo, configuración de producción y pendientes en `docs/SEGURIDAD.md`):
- Contraseñas: BCrypt (costo 12); mínimo 12 caracteres con mayúscula, minúscula, número y símbolo; sin el usuario ni palabras comunes. Bloqueo tras 3 intentos fallidos (lo libera Soporte TI/Administración).
- Sesión: cookie opaca `__Host-ESFAPSESSION` HttpOnly + Secure + SameSite=Strict; expira a los 5 min de inactividad y a las 8 h como máximo; se rota al iniciar sesión; se invalida si cambia el navegador.
- CSRF: token por sesión (cabecera `X-CSRF-TOKEN`). XSS: CSP estricta (`script-src 'self'`, sin JS inline) + salida escapada + validación en servidor. SQLi: JPA parametrizado.
- Autorización en el servidor: cada rol solo lee/escribe sus datos (`StateGuard`); Administración no puede crear ni desactivar cuentas TI/Administración.
- Datos en reposo cifrados con AES-256-GCM (estado, nombres, auditoría) y base de datos H2 cifrada en producción. El navegador no guarda nada (sin localStorage/sessionStorage).
- Límite de peticiones por IP (login, contraseña, verificación y API), cabeceras HSTS, anti-clickjacking, Permissions-Policy, COOP/CORP.
- Cifrado en tránsito: TLS 1.2+ (proxy inverso o `server.ssl`). Ley N.° 29733: ver `docs/SEGURIDAD.md`. Incidentes: notificar en 48 h (RS-04).

## Instalación
JDK 17+. STS: importar proyecto Maven y ejecutar `PortalApplication`. Consola: `mvn spring-boot:run`. Abrir http://localhost:8080
Si su navegador no acepta la cookie `__Host-` en http (p. ej. Safari o acceso por IP), use el perfil de desarrollo: `-Dspring.profiles.active=dev`. En producción use el perfil `prod` detrás de HTTPS.

## Usuarios iniciales
Al primer arranque se crean 4 usuarios (`E2024001` estudiante, `45678912` docente, `secretaria` administrativo, `soporte` TI) con contraseñas **aleatorias que se muestran una sola vez en la consola**. Guárdelas y cámbielas al ingresar.
Solo para demostración local: con el perfil `dev` se usan `Estud2026`, `Docen2026`, `Admin2026` y `Soporte2026` (no cumplen la política actual: cámbielas en cuanto ingrese).

## Manual por rol
- Estudiante: matrícula, pagos (simulados), notas, trámites con código, biblioteca, mesa de servicio.
- Docente: asistencia, notas, mesa de servicio.
- Administrativo: aprobar matrículas, conciliar pagos, emitir certificados, reportes, usuarios, auditoría.
- Soporte TI: usuarios y roles, logs, respaldos.
- Visitante: portada, carreras, biblioteca, contacto, verificación de documentos por código.
