# Single-tenant per deployment

Sésamo se despliega como una instancia por proyecto consumidor: una base, un
`SESAMO_SERVICE_TOKEN` y una configuración. El aislamiento entre proyectos es
el aislamiento entre deployments, no una columna `project_id`.

Se descartó compartir una instancia entre múltiples proyectos porque
`users.email` e `identities(provider, provider_sub)` son únicos globales,
`sessions` no tiene tenant y `/v1/introspect` devuelve una identidad sin scope
de proyecto. Agregar multi-tenancy requeriría extender el aislamiento a cada
tabla, consulta, clave de rate limit y evento de auditoría.

La identidad declarativa del deployment se configura mediante
`SESAMO_PROJECT_SLUG` y `SESAMO_PROJECT_DISPLAY_NAME`. La superficie pública de
descubrimiento incluye `GET /.well-known/sesamo`, `GET /openapi.json`,
`GET /llms.txt` y `sesamo describe --json`. Estas interfaces describen el
deployment y sus capacidades; no constituyen una frontera de autorización.
