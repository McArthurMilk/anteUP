import { Router, Request, Response } from 'express';
import { pool } from '@/db/index.js';
import { authenticate } from '@/middleware/authenticate.js';
import { toPublicUser } from '@/lib/user.js';
import type { User } from '@/types/index.js';

const router = Router();

router.use(authenticate);

// GET /api/users/me
router.get('/me', async (req: Request, res: Response) => {
  const { rows } = await pool.query<User>('SELECT * FROM users WHERE id = $1', [req.user?.sub]);
  if (!rows[0]) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  res.json({ user: toPublicUser(rows[0]) });
});

// GET /api/users
router.get('/', async (_req: Request, res: Response) => {
  try {
    const { rows } = await pool.query<User>('SELECT * FROM users ORDER BY created_at DESC');
    res.json(rows.map(toPublicUser));
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/users/:id
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query<User>('SELECT * FROM users WHERE id = $1', [req.params.id]);
    if (!rows[0]) {
      res.status(404).json({ error: 'User not found' });
      return;
    }
    res.json(toPublicUser(rows[0]));
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
