-- USERS
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  email text UNIQUE NOT NULL,
  password_hash text NOT NULL,
  email_verified boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- REFRESH TOKENS
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash bytea NOT NULL UNIQUE,
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz NULL,
  parent_id uuid NULL REFERENCES refresh_tokens(id) ON DELETE SET NULL,
  user_agent text NULL,
  ip inet NULL
);

-- AUDIT LOG (opcional)
CREATE TABLE IF NOT EXISTS auth_audit_log (
  id bigserial PRIMARY KEY,
  event text NOT NULL,
  user_id uuid NULL REFERENCES users(id) ON DELETE SET NULL,
  jti text NULL,
  refresh_id uuid NULL REFERENCES refresh_tokens(id) ON DELETE SET NULL,
  ip inet NULL,
  user_agent text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
