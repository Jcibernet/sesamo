# Single-tenant por deployment; AI-first vía descriptor, no vía tenancy

Sésamo V1 se despliega una instancia por proyecto consumidor (una base, un
`SESAMO_SERVICE_TOKEN`, una configuración). El aislamiento entre proyectos es
el aislamiento entre deployments, no una columna `project_id`.

Se consideró introducir multi-tenancy (Projects, Clients, credenciales
scoped) y se rechazó para V1: `users.email` y `identities(provider,
provider_sub)` son únicos globales, `sessions` no tiene tenant, e
`/v1/introspect` devuelve identidad sin scope sobre un contrato ya integrado.
Compartir base entre tenants convertiría el aislamiento cross-project en la
invariante de seguridad número uno y tocaría cada tabla, query y test —
incluidas las claves de rate limit `identity:<email>` (que deberían scoparse
por project mientras las `ip:` permanecen globales) y `audit_log`, que
necesitaría `project_id` propio porque `actor_user` es nullable.

Lo que sí es V1: identidad declarativa del deployment
(`SESAMO_PROJECT_SLUG`, `SESAMO_PROJECT_DISPLAY_NAME`) y una superficie
AI-first de solo lectura — `GET /.well-known/sesamo` (descriptor derivado de
las constantes del código, nunca redactado a mano), `GET /openapi.json`,
`GET /llms.txt` y `sesamo describe --json` — para que un agente configure la
integración sin leer prosa. El data plane de autenticación permanece
determinista; AI-first califica a las interfaces de operación, no al
mecanismo de auth.
