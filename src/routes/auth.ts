import { Router, Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import { z } from 'zod';
import { pool } from '@/db/index.js';
import { env } from '@/env.js';
import { authenticate } from '@/middleware/authenticate.js';
import type { User, RefreshToken } from '@/types/index.js';
import { toPublicUser } from '@/lib/user.js';

const router = Router();

// Schemas for our route validation
const registerSchema = z.object({
  name: z.string().min(1),
  email: z.email(),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

const loginSchema = z.object({
  email: z.email(),
  password: z.string().min(1),
});

const refreshSchema = z.object({
  refresh_token: z.string().min(1),
});

// Token helpers
function signAccessToken(user: User): string {
  return jwt.sign({ sub: user.id, email: user.email }, env.JWT_SECRET, {
    expiresIn: env.JWT_EXPIRES_IN,
  });
}

async function createRefreshToken(userId: string): Promise<string> {
  const token = crypto.randomBytes(64).toString('hex');
  const expires_at = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await pool.query(
    `INSERT INTO refresh_tokens (user_id, token, expires_at)
     VALUES ($1, $2, $3)`,
    [userId, token, expires_at],
  );

  return token;
}

// POST /api/auth/register
router.post('/register', async (req: Request, res: Response) => {
  const result = registerSchema.safeParse(req.body);

  if (!result.success) {
    res.status(400).json({ error: z.flattenError(result.error).fieldErrors });
    return;
  }

  const { name, email, password } = result.data;

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows[0]) {
      res.status(409).json({ error: 'Email already in use' });
      return;
    }

    const password_hash = await bcrypt.hash(password, env.BCRYPT_ROUNDS);

    const { rows } = await pool.query<User>(
      `INSERT INTO users (name, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [name, email, password_hash],
    );

    const user = rows[0];
    const access_token = signAccessToken(user);
    const refresh_token = await createRefreshToken(user.id);

    res.status(201).json({ user: toPublicUser(user), access_token, refresh_token });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/login
router.post('/login', async (req: Request, res: Response) => {
  const result = loginSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ error: z.flattenError(result.error).fieldErrors });
    return;
  }

  const { email, password } = result.data;

  try {
    const { rows } = await pool.query<User>('SELECT * FROM users WHERE email = $1', [email]);

    const user = rows[0] ?? null;

    /**
     * NOTE: Why are we hashing if the user isn't found?
     *
     * If we returned early when no user is found, an attacker could measure
     * response times to determine whether an email is registered.
     * By always running bcrypt.compare against a dummy hash, both branches take roughly the same time.
     *
     * This is a partial mitigation. bcrypt timing varies slightly run to run,
     * and enumeration is often possible through other vectors (registration,
     * password reset). Rate limiting auth routes is a better approach.
     *
     * The above is also a trade off and can be a UX decision (ever been annoyed by "Invalid username or password"?)
     *
     * Read more here https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
     */

    const hash = user?.password_hash ?? '$2b$12$invalidhashfortimingpurposes00000000000';
    const match = await bcrypt.compare(password, hash);

    if (!user || !match) {
      res.status(401).json({ error: 'Invalid email or password' }); // See above
      return;
    }

    const access_token = signAccessToken(user);
    const refresh_token = await createRefreshToken(user.id);

    res.json({ user: toPublicUser(user), access_token, refresh_token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/refresh
router.post('/refresh', async (req: Request, res: Response) => {
  const result = refreshSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ error: z.flattenError(result.error).fieldErrors });
    return;
  }

  const { refresh_token } = result.data;

  try {
    const { rows } = await pool.query<RefreshToken>(
      `SELECT * FROM refresh_tokens WHERE token = $1`,
      [refresh_token],
    );

    const stored = rows[0];

    if (!stored || stored.expires_at < new Date()) {
      res.status(401).json({ error: 'Invalid or expired refresh token' });
      return;
    }

    // Rotate: delete old token, issue new one
    await pool.query('DELETE FROM refresh_tokens WHERE id = $1', [stored.id]);

    const { rows: userRows } = await pool.query<User>('SELECT * FROM users WHERE id = $1', [
      stored.user_id,
    ]);

    const user = userRows[0];
    if (!user) {
      res.status(401).json({ error: 'User not found' });
      return;
    }

    const access_token = signAccessToken(user);
    const newRefreshToken = await createRefreshToken(user.id);

    res.json({ access_token, refresh_token: newRefreshToken });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/logout
router.post('/logout', authenticate, async (req: Request, res: Response) => {
  const result = refreshSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ error: z.flattenError(result.error).fieldErrors });
    return;
  }

  try {
    // Scope deletion to the authenticated user to prevent token hijacking
    await pool.query('DELETE FROM refresh_tokens WHERE token = $1 AND user_id = $2', [
      result.data.refresh_token,
      req.user?.sub,
    ]);

    res.json({ message: 'Logged out' });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
