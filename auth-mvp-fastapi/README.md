# Auth MVP (FastAPI)

Módulo de autenticación **JWT (access)** + **refresh tokens con rotación** (solo hash en DB).

## Stack
- Python 3.11+
- FastAPI
- Uvicorn
- SQLAlchemy 2.x (async) + asyncpg
- Alembic
- bcrypt para passwords
- HS256 para `access` (MVP; migrable a RS256)
- Postgres

## Estructura de carpetas (Clean-ish)
```
app/
  api/               # Routers HTTP (un archivo por contexto)
  service/           # Reglas de negocio
  models/            # Entidades (Pydantic + ORM)
  db/                # Infra DB (session, repos, migrations)
  utils/             # Helpers (hashing, JWT, rate limit, etc.)
  core/              # Configuración, errores, constants
tests/
migrations/          # Alembic
```

El flujo esperado: `api.producto -> service.producto -> db.producto -> service.producto -> models.product -> service.producto -> utils.product` (adaptado para el contexto de **auth**).

Los requerimientos y el diagrama provienen de tus archivos adjuntos.
Ver **.env.example** y **docker-compose.yml** para correr el proyecto.
