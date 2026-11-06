# Sandesh — Backend

The Sandesh backend is a standalone Node.js/Express service backed by MongoDB. It is deployed independently from the frontend (for example, as a persistent service on Render). It provides the API and optional Socket.IO server used by the frontend.

## Features

- Username/password authentication with JWTs and bcrypt password hashing.
- One-to-one conversations identified by their two participants.
- Authorization checks for conversation membership and administrator actions.
- Storage and retrieval of encrypted message payloads; soft-delete support.
- Crypto-device registration, approval, and encrypted conversation-key envelopes.
- Socket.IO events for private realtime chat, with frontend polling as a fallback.
- Health endpoints, request validation, login rate limiting, Helmet headers, and configurable CORS.
- Optional Telegram-controlled terminal-output forwarding for a persistent Node process.

## Technology

- Node.js `^20.19.0` or `>=22.12.0`.
- Express 4, Mongoose 8, and MongoDB.
- JWT (`jsonwebtoken`) and `bcryptjs`.
- Socket.IO 4, CORS, Helmet, express-rate-limit, express-validator, and Morgan.
- Optional Telegraf integration for Telegram terminal logging.

## Project layout

```text
backend.js                 Express app, models, API routes, and Socket.IO startup
CONST.js                   Runtime configuration defaults sourced from environment
api/                       Serverless request wrappers (not required for Render)
telegramTerminalLogger.js  Optional Telegram terminal logger
resetAdminPassword.js      Admin password management utility
.env.example               Optional Telegram environment example
```

## Requirements and local setup

1. Install Node.js and MongoDB (local MongoDB or a reachable MongoDB deployment).
2. From this directory, install dependencies:

   ```sh
   npm ci
   ```

3. Configure the environment variables below. For local development, create a private `.env` file or supply environment variables through your shell. Never commit secrets.
4. Start the server:

   ```sh
   npm run dev     # nodemon backend.js
   npm start       # node backend.js
   ```

The default port is `3001`; the server uses `PORT` when provided by the host. Check `GET /api/health` to see service, database, and realtime status.

## Configuration

`CONST.js` reads the following environment variables:

| Variable | Purpose | Production guidance |
|---|---|---|
| `PORT` | HTTP and Socket.IO listener port | Usually supplied by the hosting platform. |
| `MONGODB_URI` | MongoDB connection string | Required; use a private, least-privilege database credential. |
| `JWT_SECRET` | Signs and verifies session JWTs | Required; use a long, unique secret. |
| `CORS_ORIGIN` | Comma-separated allowed browser origin(s) | Required in production; do not use `*`. Use the frontend's exact HTTPS origin. |
| `ADMIN_USERNAME` | Seeded administrator username; defaults to `Viparyas` | Configure intentionally. Only the configured admin username can be created with the admin role. |
| `ADMIN_PASSWORD` | Password for the seeded administrator account | Set a strong value before first startup. Never use the development default in production. |
| `MESSAGE_LIMIT` | Maximum retained messages per conversation | Defaults to `100`; older messages are periodically removed. |
| `MAX_TEXT_LENGTH` | Maximum plaintext message length accepted by the client | Defaults to `600` characters. Encrypted payloads are larger on the wire. |
| `BCRYPT_ROUNDS` | Password hashing work factor | Defaults to `12`. |
| `MONGODB_SERVER_SELECTION_TIMEOUT_MS` | MongoDB server selection timeout | Optional; defaults to `10000`. |
| `MONGODB_SOCKET_TIMEOUT_MS` | MongoDB socket timeout | Optional; defaults to `20000`. |
| `MONGODB_MAX_POOL_SIZE` | Maximum MongoDB connection pool size | Optional; defaults to `10`. |
| `TELEGRAM_BOT_TOKEN` | Optional bot token for terminal logger | Leave unset to disable. |
| `TELEGRAM_LOG_ALLOWED_USER_IDS` | Comma-separated Telegram IDs or usernames allowed to control logging | Required with the bot token; prefer numeric IDs. |

Production startup rejects placeholder/missing MongoDB and JWT configuration and wildcard CORS. If the admin account must be seeded, set `ADMIN_PASSWORD` securely before startup; do not rely on the development fallback.

## Render deployment

Deploy this backend directory as a Node web service:

1. Set the build/install command to `npm ci`.
2. Set the start command to `npm start`.
3. Add the required environment variables in Render's environment settings: `MONGODB_URI`, `JWT_SECRET`, and `CORS_ORIGIN`; also set `ADMIN_USERNAME` and `ADMIN_PASSWORD` for initial admin seeding.
4. Set `CORS_ORIGIN` to the frontend's exact deployed origin (no wildcard).
5. Use Render's assigned `PORT` and confirm `https://<backend-host>/api/health` responds.
6. Configure the separate frontend deployment with the backend's public origin as `VITE_API_BASE`.

The normal `npm start` process creates a persistent HTTP server and attaches Socket.IO. The `api/` wrappers are for serverless-style hosting and are not needed for a persistent Render service; serverless deployments may not provide durable Socket.IO connections, in which case the frontend uses polling.

## HTTP API

All routes are under `/api`. Protected routes require `Authorization: Bearer <JWT>`.

### Health and authentication

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api` | Basic service response. |
| `GET` | `/api/health` | Service, MongoDB, and realtime readiness information. |
| `POST` | `/api/auth/login` | Validate username/password and issue a JWT. |
| `GET` | `/api/auth/me` | Return the authenticated user's summary. |

### Administrator routes

Admin routes require an authenticated administrator:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/admin/users` | List user summaries. |
| `POST` | `/api/admin/create-user` | Create a user (or the configured admin account). |
| `POST` | `/api/admin/ban-user` | Ban or unban a user. |
| `DELETE` | `/api/admin/users/:id` | Delete a user. |
| `POST` | `/api/admin/reset-password` | Reset a user's password. |

### Conversations, messages, and encryption devices

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/chat/conversations` | List the signed-in user's conversations and latest message previews. |
| `POST` | `/api/chat/conversations` | Find or create a one-to-one conversation by username. |
| `GET` | `/api/chat/conversations/:conversationId/messages` | Load conversation history; accepts optional `since` cursor. |
| `POST` | `/api/chat/conversations/:conversationId/messages` | Create a conversation message; only supported encrypted payloads are accepted. |
| `DELETE` | `/api/chat/messages/:id` | Soft-delete a message if permitted. |
| `POST` | `/api/crypto/devices/register` | Register a browser device and its public key. |
| `GET` | `/api/crypto/devices` | List the account's crypto devices and approval states. |
| `GET` | `/api/crypto/devices/pending` | List devices awaiting approval. |
| `POST` | `/api/crypto/devices/:deviceId/approve` | Approve a pending device from an approved device. |
| `GET` | `/api/chat/conversations/:conversationId/keys` | Get approved device public keys and this device's key envelope. |
| `POST` | `/api/chat/conversations/:conversationId/keys/claim` | Claim the conversation's initial encryption key ID. |
| `POST` | `/api/chat/conversations/:conversationId/keys/envelopes` | Store an encrypted conversation-key envelope for an approved device. |
| `GET` | `/api/chat/messages` | Read legacy shared-room history, if present. |
| `POST` | `/api/chat/messages` | Disabled; returns HTTP `410`. |

The server checks authentication, conversation membership, device ownership/approval, request shape, and encrypted-message format. It stores ciphertext for newly encrypted messages and never receives their plaintext from the supported frontend.

## Socket.IO events

Socket connections authenticate with the user's JWT. Conversation room membership is checked before joining.

- Client → server: `chat:join`, `chat:leave`, `chat:send`, `chat:delete`.
- Server → client: `chat:newMessage`, `chat:deleted`.
- `chat:send` accepts encrypted conversation-message payloads only.
- If a socket connection is unavailable, the frontend uses HTTP APIs and polling instead.

## Data and retention

- Users store normalized usernames, password hashes, role, ban state, and timestamps.
- Conversations store their participants, latest-message timestamp, and encryption key ID.
- Messages store the encrypted payload for new messages, sender/reply metadata, deletion state, and timestamp. Legacy history may still be plaintext.
- Crypto devices store account association, device ID, public JWK, and approval state. Private keys remain in the browser's IndexedDB.
- Conversation key envelopes are encrypted for an approved device; the server stores but cannot decrypt the envelope.
- The newest `MESSAGE_LIMIT` messages per conversation are retained. Older records are removed by background trimming.

## Security notes

- Use HTTPS for deployed frontend and backend, unique production secrets, and a restrictive CORS allowlist.
- Message encryption uses AES-GCM in the browser. Device key transfer uses ECDH P-256.
- Peer device keys are not independently authenticated or verified out of band. A compromised backend could substitute public keys; encryption does not defend against that active server-side attack.
- A compromised browser, device, frontend origin, or an account session can expose plaintext or keys.
- The backend's legacy shared-room message creation endpoint is disabled; legacy history may still be returned by its read endpoint.

## Telegram terminal logging and device approval

Terminal logging is disabled unless both `TELEGRAM_BOT_TOKEN` and `TELEGRAM_LOG_ALLOWED_USER_IDS` are configured. It is intended for the persistent Node server, not a serverless deployment.

In a private chat with the bot, authorized users can use:

- `/startlog` to begin receiving batched process output.
- `/stoplog` to stop forwarding output.
- `/logstatus` to check the current state.
- `/deviceapproval list` to list pending devices across accounts.
- `/deviceapproval <username> <device-id> approve` to approve one pending device.
- `/deviceapproval <username> <device-id> reject` to reject one pending device.

Device approval commands are accepted only in private chats and require the sender's numeric Telegram user ID or Telegram username to be present in `TELEGRAM_LOG_ALLOWED_USER_IDS`. Numeric IDs are safer because usernames can change or be reassigned. Keep this allowlist restricted to trusted administrators.

The pending-device list includes each account username and unique device ID. Copy both values exactly into an approve or reject command. Telegram approval resets the encryption key IDs for that account's conversations so the newly approved device can establish fresh keys. The new device cannot recover old keys from Telegram or the backend; existing encrypted history may become unreadable on clients that replace their cached keys. Prefer approval from an already approved browser when preserving encrypted history matters.

Terminal output can contain sensitive operational details; common token, password, authorization, and MongoDB password patterns are masked, but masking cannot guarantee that all secrets are removed.
