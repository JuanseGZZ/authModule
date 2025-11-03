
# auth-mvp (FastAPI + PostgreSQL)

MVP del módulo de autenticación con:
- JWS RS256 firmado y JWE anidado para el access token
- Refresh token opaco (hash SHA-256) con rotación
- JWKS público en `/.well-known/jwks.json`
- Front-side encryption opcional vía campo `__front_enc__` (JWE)

## Requisitos
Python 3.11+, dependencias:
```
pip install fastapi uvicorn psycopg[binary] bcrypt cryptography
```
Base de datos PostgreSQL con extensión `pgcrypto` o `pguuid` (para `gen_random_uuid()`). En Debian/Ubuntu:
```
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```
Configurar variable `DB_DSN` si no usás la por defecto.

## Ejecutar
```
uvicorn main:app --reload
```

## Notas
- Claves se generan en caliente (ephemerales). **TODO**: integrar KMS/FILE y rotación según YAML.
- Esquema creado automáticamente (MVP). **TODO**: migraciones reales.
- Formato de errores: las rutas devuelven `{"error": {"code","message"}}` ante fallas.
- Si el YAML requiere campos adicionales en claims o políticas específicas, marcadas como **TODO**.
