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
import { getDummyHash } from '@/lib/auth.js';

const router = Router();

/*
 * We validate all request bodies with Zod before touching the database.
 * This gives us type-safe data and clear error messages for free.
 * NOTE: A common pattern you will see is :
 *
 *  const result = registerSchema.safeParse(req.body);
 *
 *  if (!result.success) {
 *    res.status(400).json({ error: z.flattenError(result.error).fieldErrors });
 *    return;
 *  }
 *
 * Essentially, we can define our request shapes, and then parse them and extract errors trivially
 */
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

/**
 * Signs a short-lived JWT access token for the given user.
 *
 * NOTE: Access tokens are stateless, meaning that once issued, they cannot be revoked
 * before expiry (configured via JWT_EXPIRES_IN, our default being 900 seconds, or 15 minutes).
 * This is a fundamental tradeoff of JWTs. If you need immediate revocation
 * (e.g. on logout or account ban), you'd need a token denylist, which
 * reintroduces statefulness. For most apps, short expiry + refresh rotation
 * is an acceptable middle ground.
 */
function signAccessToken(user: User): string {
  return jwt.sign({ sub: user.id, email: user.email }, env.JWT_SECRET, {
    expiresIn: env.JWT_EXPIRES_IN,
  });
}

/**
 * Creates a new refresh token and persists it to the database.
 *
 * NOTE: Refresh tokens are long-lived (7 days here) and stateful; they live
 * in the database and can be revoked at any time. This is intentional.
 * Unlike access tokens, refresh tokens are only sent to one endpoint (/refresh),
 * reducing their exposure surface.
 *
 * NOTE: familyId groups tokens that were rotated from the same original login.
 * When reuse is detected on any token in a family, we invalidate the whole
 * family. See /refresh for the full explanation.
 *
 * @param userId - The user this token belongs to
 * @param familyId - Optional: carry forward from a previous token in the chain.
 *                   If omitted, a new family is started (i.e. fresh login).
 */
async function createRefreshToken(
  userId: string,
  familyId?: string,
): Promise<{ token: string; familyId: string }> {
  const token = crypto.randomBytes(64).toString('hex');
  const resolvedFamilyId = familyId ?? crypto.randomUUID();
  const expires_at = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await pool.query(
    `INSERT INTO refresh_tokens (user_id, family_id, token, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [userId, resolvedFamilyId, token, expires_at],
  );

  return { token, familyId: resolvedFamilyId };
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
    // Check that its not registered already
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows[0]) {
      res.status(409).json({ error: 'Email already in use' });
      return;
    }

    // NOTE: bcrypt.hash is intentionally slow (controlled by BCRYPT_ROUNDS).
    // This is the point, it makes brute-forcing hashed passwords expensive.
    const password_hash = await bcrypt.hash(password, env.BCRYPT_ROUNDS);

    const { rows } = await pool.query<User>(
      `INSERT INTO users (name, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [name, email, password_hash],
    );

    const user = rows[0];
    const access_token = signAccessToken(user);
    const { token: refresh_token } = await createRefreshToken(user.id);

    // NOTE: We return the access token in the response body (to be stored in
    // memory by the client) and the refresh token similarly.
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

    // NOTE: Timing attack mitigation.
    // If we returned early when no user is found, an attacker could measure
    // response times to infer whether an email is registered. bcrypt.compare
    // takes ~250ms, but an early return takes microseconds.
    // By always running bcrypt.compare (against a dummy hash when no user is
    // found), both code paths take roughly the same time.
    //
    // WARNING: This is a partial mitigation. bcrypt timing varies slightly
    // run to run, and enumeration is often possible through other vectors
    // (e.g. registration returning 409, password reset flows).
    // Rate limiting auth routes is a more robust defense.
    //
    // INFO: Always hashing has a UX cost: "Invalid email or password" is
    // less helpful than "Email not found". This is a deliberate security/UX
    // decision. Some apps (e.g. banks) always obscure; others (e.g. Google)
    // confirm email existence explicitly.
    const hash = user?.password_hash ?? (await getDummyHash());
    const match = await bcrypt.compare(password, hash);

    if (!user || !match) {
      res.status(401).json({ error: 'Invalid email or password' });
      return;
    }

    const access_token = signAccessToken(user);
    const { token: refresh_token } = await createRefreshToken(user.id);

    res.json({ user: toPublicUser(user), access_token, refresh_token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/*
 * POST /api/auth/refresh
 *
 * Refresh token rotation: each use of a refresh token invalidates it and
 * issues a new one. This limits the damage of a stolen refresh token to a
 * single use before the legitimate client rotates it and the attacker's
 * copy becomes invalid.
 *
 * EXPLORE: What happens if the legitimate client's request and the attacker's
 * request arrive at the same time? This is a known limitation of rotation
 * without strict locking. SELECT FOR UPDATE can help in production.
 */

router.post('/refresh', async (req: Request, res: Response) => {
  const result = refreshSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ error: z.flattenError(result.error).fieldErrors });
    return;
  }

  const { refresh_token } = result.data;

  try {
    // Check if this token exists in the database
    const { rows } = await pool.query<RefreshToken>(
      `SELECT * FROM refresh_tokens WHERE token = $1`,
      [refresh_token],
    );

    const stored = rows[0];

    // Unknown or forged token, not in the database at all.
    if (!stored) {
      res.status(401).json({ error: 'Invalid or expired refresh token' });
      return;
    }

    // NOTE: Reuse detection via consumed_at.
    //
    // When a refresh token is used, we don't delete it, instead we mark it consumed.
    // This is intentional: if we deleted it, we'd lose the ability to detect
    // reuse. A consumed token being presented again means either:
    //   a) The legitimate client is retrying a failed request (unlikely but possible), or
    //   b) An attacker has obtained a previously used token.
    //
    // We assume (b) and invalidate the entire family, all tokens that share
    // the same origin login. This forces the legitimate user to log in again (on all sessions),
    // which is disruptive but safe.

    // Token has been consumed already, invalidate entire family
    if (stored.consumed_at !== null) {
      await pool.query(`DELETE FROM refresh_tokens WHERE family_id = $1`, [stored.family_id]);
      res.status(401).json({ error: 'Refresh token reuse detected. Please log in again.' });
      return;
    }

    // Token is expired, clean it up and reject.
    if (stored.expires_at < new Date()) {
      await pool.query(`DELETE FROM refresh_tokens WHERE id = $1`, [stored.id]);
      res.status(401).json({ error: 'Invalid or expired refresh token' });
      return;
    }

    // Valid token (mark as consumed, fetch user, and rotate)
    // We mark consumed BEFORE issuing the new token. If the insert fails
    // after this point, the user will need to log in again. This is preferable
    // to the alternative: issuing a new token before marking consumed, which
    // could leave two valid tokens alive simultaneously.
    await pool.query(`UPDATE refresh_tokens SET consumed_at = NOW() WHERE id = $1`, [stored.id]);

    const { rows: userRows } = await pool.query<User>(`SELECT * FROM users WHERE id = $1`, [
      stored.user_id,
    ]);

    const user = userRows[0];
    if (!user) {
      res.status(401).json({ error: 'User not found' });
      return;
    }

    const access_token = signAccessToken(user);
    const { token: newRefreshToken } = await createRefreshToken(user.id, stored.family_id);

    res.json({ access_token, refresh_token: newRefreshToken });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

/*
 * POST /api/auth/logout
 *
 * NOTE: Logout only invalidates refresh tokens, meaning that the access token remains
 * valid until it expires naturally. This is a fundamental limitation of
 * stateless JWTs. The client is responsible for discarding the access token
 * on logout.
 */
router.post('/logout', authenticate, async (req: Request, res: Response) => {
  const result = refreshSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ error: z.flattenError(result.error).fieldErrors });
    return;
  }

  try {
    // NOTE: We filter by both token AND user_id to prevent a user from
    // logging out another user's session by submitting their refresh token.
    const { rows } = await pool.query<RefreshToken>(
      `SELECT family_id FROM refresh_tokens WHERE token = $1 AND user_id = $2`,
      [result.data.refresh_token, req.user?.sub],
    );

    const stored = rows[0];
    if (stored) {
      // Invalidate the entire family, not just this token: this logs out
      // all devices/sessions that share the same origin login.
      //
      // QUESTION: How would you support "logout this device only" vs
      // "logout all devices"? What schema changes would that require?
      //
      // HINT: Each token could store a device_name/session_id, and you'd delete by token
      // instead of family_id for single-device logout.
      await pool.query(`DELETE FROM refresh_tokens WHERE family_id = $1`, [stored.family_id]);
    }

    // NOTE: We return 200 even if no token was found. Logout should be
    // idempotent, the client's goal (session invalidated) is achieved
    // either way, and leaking whether a token existed is unnecessary.
    res.json({ message: 'Logged out' });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
