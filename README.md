# Sandesh Backend Summary

This README explains how the backend is built at a high level.
Sensitive values such as database connection strings, secrets, passwords, and private deployment details are intentionally not included.

## What this backend is

The backend is a Node.js service built around Express and MongoDB. It powers:

- authentication
- user/admin management
- chat message storage
- message moderation
- optional real-time delivery through Socket.IO

## Main stack

- Node.js
- Express
- MongoDB with Mongoose
- JWT authentication
- `bcryptjs` for password hashing
- Socket.IO
- `helmet`
- `cors`
- `express-rate-limit`
- `express-validator`
- `xss`
- `morgan`
- `telegraf` (optional Telegram terminal-log controls)

## How the backend is organized

- `backend.js` is the main application file.
- It contains the Express app setup, middleware, MongoDB models, auth logic, admin logic, chat routes, and optional socket bootstrapping.
- `api/` contains lightweight wrappers that forward serverless requests to the same Express app.
- Runtime settings are loaded from environment/local config sources rather than being documented with real values here.

## Core responsibilities

- authenticate users with username and password
- issue JWTs after login
- load the current user from the token
- protect admin-only actions
- store and fetch chat messages
- support message replies
- soft-delete messages
- manage banned users
- disconnect banned users from live sessions when possible

## Data model at a high level

- Users include identity, normalized username, hashed password, role, banned state, and timestamps.
- Chat messages include text, sender details, reply metadata, deleted state, and timestamps.

## API shape

- auth routes handle login and current-session lookup
- admin routes handle listing users, creating users, banning/unbanning, deleting users, and resetting passwords
- chat routes handle fetching, creating, and deleting messages
- health routes expose a simple readiness/status response

## Realtime and deployment behavior

- When `backend.js` runs as a normal Node server, it creates an HTTP server and attaches Socket.IO.
- In that mode, new messages and deletions can be pushed instantly to connected clients.
- The `api/` wrapper files let the same app work in serverless-style deployments.
- If a deployment cannot keep long-lived sockets, the frontend can continue to work through HTTP polling.

## Security and safety measures

- passwords are hashed before storage
- private routes require JWT auth
- admin actions require role checks
- login attempts are rate-limited
- request bodies are validated
- chat text is sanitized
- CORS is configurable and tightened for production use
- production startup checks reject unsafe placeholder config for critical settings

## Data retention behavior

- The chat history is capped to a configured message limit.
- Older messages are trimmed so only the newest set is kept.

## Sensitive information

This README intentionally does not include:

- database URLs
- JWT secrets
- passwords
- live tokens
- private deployment origins

## Optional Telegram terminal logging

When running the persistent Node server (not a serverless deployment), you can forward
that Node process's stdout and stderr to Telegram on demand. Add the following values
to `.env` (see `.env.example`):

```env
TELEGRAM_BOT_TOKEN=your-bot-token
TELEGRAM_LOG_ALLOWED_USER_IDS=your-numeric-telegram-user-id
```

Only listed Telegram user IDs can control the logger, and commands are accepted only in
private chats with the bot. Numeric user IDs are recommended; usernames are also accepted
for convenience but can change over time. Send `/startlog` to begin receiving batched
terminal output, `/stoplog` to stop, and `/logstatus` to check the current state. Terminal
output can contain sensitive information; the logger masks common token, password, and
MongoDB password patterns, but you should still grant access only to trusted administrators.
