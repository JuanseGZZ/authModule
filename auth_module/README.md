# Auth Module (FastAPI) — per `req.back.v3.2.yml`

This repository implements the authentication module **exactly** following the YAML file you provided. 
Where the YAML is silent, the code includes `TODO` markers to be completed once those fields are specified.

## Endpoints
- `GET /.well-known/jwks.json`
- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/token/refresh`
- `POST /auth/logout`
- `GET /auth/me`

Access tokens are **JWS** (RS256/ES256) **nested** inside **JWE** (RSA‑OAEP‑256 / ECDH‑ES+A256KW + A256GCM).  
Refresh tokens are **opaque** with **mandatory rotation** and **reuse detection**.  
JWKS publishes `use=sig|enc|enc_front` with `kid`, including grace keys during rotation.  
`__front_enc__` is accepted on target endpoints and decrypted first.  
Rate limit, security headers, CORS, audit logs included.

See `SPEC_RAW.yml` for the authoritative spec.