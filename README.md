# Ante

A minimal Express + PostgreSQL + TypeScript starter demonstrating authentication concepts. Built for lecture use. After some more migration and development, this will be our final project repo.

## Stack

- **Runtime**: Node 22
- **Framework**: [Express](https://expressjs.com/)
- **Database**: [PostgreSQL 16](https://www.postgresql.org/docs/) via [`node-postgres`](https://node-postgres.com/)
- **Auth**: [bcrypt](https://github.com/kelektiv/node.bcrypt.js) + [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken)
- **Validation**: [Zod](https://zod.dev)
- **TypeScript**: [tsx](https://github.com/privatenumber/tsx) for dev, `tsc` for builds

---

## Getting Started

### 1. Install dependencies

```bash
npm install
```

### 2. Configure environment

Copy the example env file and adjust if needed:

```bash
cp .env.example .env
```

Generate a secure JWT secret:

```bash
openssl rand -hex 32
```

### 3. Start the database

```bash
npm run docker:db
```

### 4. Start the API

```bash
npm run dev
```

Or run both in Docker:

```bash
npm run docker:api
```

---

## Scripts

| Script                 | Description                       |
| ---------------------- | --------------------------------- |
| `npm run dev`          | Start API locally with hot reload |
| `npm run docker:db`    | Start only the Postgres container |
| `npm run docker:api`   | Start API + Postgres in Docker    |
| `npm run docker:down`  | Stop containers                   |
| `npm run docker:reset` | Stop containers and wipe volumes  |

---

## API

### Auth

| Method | Path                 | Auth | Description                           |
| ------ | -------------------- | ---- | ------------------------------------- |
| `POST` | `/api/auth/register` | ✗    | Register a new user                   |
| `POST` | `/api/auth/login`    | ✗    | Login, receive tokens                 |
| `POST` | `/api/auth/refresh`  | ✗    | Exchange refresh token for new tokens |
| `POST` | `/api/auth/logout`   | ✓    | Invalidate refresh token              |

#### `POST /api/auth/register`

```json
{
  "name": "Gabriel",
  "email": "gabriel@example.com",
  "password": "password123"
}
```

Response `201`:

```json
{
  "user": {
    "id": "uuid",
    "name": "Gabriel",
    "email": "gabriel@example.com",
    "created_at": "..."
  },
  "token": "<jwt>"
}
```

#### `POST /api/auth/login`

```json
{
  "email": "gabriel@example.com",
  "password": "password123"
}
```

Response `200`:

```json
{
  "user": { "..." },
  "token": "<jwt>"
}
```

### Users

All `/api/users` routes require a `Authorization: Bearer <token>` header.

| Method | Path             | Description                 |
| ------ | ---------------- | --------------------------- |
| `GET`  | `/api/users/me`  | Get current user from token |
| `GET`  | `/api/users`     | List all users              |
| `GET`  | `/api/users/:id` | Get a user by ID            |

---

## Auth Concepts

### Password Hashing

Passwords are never stored in plain text. We use `bcrypt` to hash them before saving:

```ts
const hash = await bcrypt.hash(password, rounds);
await bcrypt.compare(plaintext, hash);
```

`rounds` controls the cost factor — how long hashing takes. Higher = slower = harder to brute force. At 12 rounds, a single hash takes ~250ms. See [bcrypt rounds](https://github.com/kelektiv/node.bcrypt.js#a-note-on-rounds).

### JSON Web Tokens (Access Tokens)

On login, the server signs a short-lived JWT (15m) with a secret key:

```ts
jwt.sign({ sub: user.id, email }, secret, { expiresIn: '15m' });
```

The client sends it on subsequent requests:

```
Authorization: Bearer <token>
```

JWTs are **stateless** — the server verifies them without a DB lookup. The tradeoff is they can't be invalidated before expiry. See [jwt.io](https://jwt.io) to inspect tokens.

### Refresh Tokens

A long-lived opaque token (7 days) stored in the database. Used to issue new access tokens without re-logging in.

On each use the token is **rotated** — the old one is deleted and a new one is issued. This means:

- Logout is real: delete the refresh token from the DB
- If a token is stolen and used first, the legitimate user's next refresh will fail

See [Auth0: Refresh Tokens](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/).

### SSO / OAuth _(further reading)_

Delegate auth to a third party (Google, GitHub, etc.) using [OAuth 2.0](https://oauth.net/2/) + [OIDC](https://openid.net/developers/how-connect-works/). In Node, [`passport.js`](https://www.passportjs.org/) is the common integration layer.

### A note on `.js` imports in TypeScript

With `NodeNext` module resolution, relative imports use `.js` extensions even in `.ts` files:

```ts
import { pool } from '@/db/pool.js';
```

TypeScript resolves these to the `.ts` source at compile time. Node expects `.js` at runtime after compilation. `tsx` handles this transparently in dev. See [TypeScript ESM docs](https://www.typescriptlang.org/docs/handbook/esm-node.html).

---

## Further Reading

| Topic                 | Link                                                                             |
| --------------------- | -------------------------------------------------------------------------------- |
| Zod                   | <https://zod.dev>                                                                |
| JWT                   | <https://jwt.io/introduction>                                                    |
| bcrypt rounds         | <https://github.com/kelektiv/node.bcrypt.js#a-note-on-rounds>                    |
| Refresh tokens        | <https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/>      |
| OWASP auth cheatsheet | <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> |
| Timing attacks        | <https://en.wikipedia.org/wiki/Timing_attack>                                    |
| OAuth 2.0             | <https://oauth.net/2/>                                                           |
| Passport.js           | <https://www.passportjs.org/>                                                    |
| TypeScript ESM        | <https://www.typescriptlang.org/docs/handbook/esm-node.html>                     |
| node-postgres         | <https://node-postgres.com/>                                                     |
| Express 5             | <https://expressjs.com/en/5x/api.html>                                           |
