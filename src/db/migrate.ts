import { pool } from '@/db/pool.js';

export async function migrate(): Promise<void> {
  const client = await pool.connect();
  // NOTE: pgcrypto provides gen_random_uuid() for UUID primary keys
  try {
    await client.query(`
      CREATE EXTENSION IF NOT EXISTS "pgcrypto";

      CREATE TABLE IF NOT EXISTS users (
        id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        name          TEXT        NOT NULL,
        email         TEXT        NOT NULL UNIQUE,
        password_hash TEXT        NOT NULL,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS users_email_idx ON users(email);

      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token      TEXT        NOT NULL UNIQUE,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      ALTER TABLE refresh_tokens
        ADD COLUMN IF NOT EXISTS family_id UUID NOT NULL DEFAULT gen_random_uuid(),
        ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;

      CREATE INDEX IF NOT EXISTS refresh_tokens_token_idx     ON refresh_tokens(token);
      CREATE INDEX IF NOT EXISTS refresh_tokens_user_id_idx   ON refresh_tokens(user_id);
      CREATE INDEX IF NOT EXISTS refresh_tokens_family_id_idx ON refresh_tokens(family_id);
    `);
    console.log('Migrations complete');
  } finally {
    client.release();
  }
}
