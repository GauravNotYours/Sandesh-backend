# Sandesh (Express + MongoDB backend)

## Requirements

- MongoDB connection string
- A JWT secret

## Configure `CONST` env file

This backend loads environment variables from the file named `CONST` in this folder (as requested), plus optionally `.env`.

Edit: `Sandesh backend/CONST`
- `MONGODB_URI=...`
- `JWT_SECRET=...`
- `ADMIN_USERNAME=Viparyas`
- `ADMIN_PASSWORD=...`
- `CORS_ORIGIN=...` (frontend origin)

## Local run

1. Install dependencies:
   - `npm install`
2. Start:
   - `npm run start`

Backend listens on `http://localhost:3001` by default.

## Important endpoints

- `POST /api/auth/login` (username + password)
- `GET /api/auth/me`
- `GET /api/admin/users`
- `POST /api/admin/create-user`
- `POST /api/admin/ban-user`
- `DELETE /api/admin/users/:id`
- `GET /api/chat/messages?since=<ms>`
- `POST /api/chat/messages` (text + optional `replyToId`)

## Messages limit (100)

After every send, the backend trims the chat collection so it keeps only the latest `MESSAGE_LIMIT` messages (default `100`).

## Real-time chat (Socket.io)

When you run this backend as a persistent server (`node backend.js`), it also starts Socket.io on the same port.
New messages are broadcast to all connected clients as `chat:newMessage`.

## Vercel note

This backend exports an Express app and includes a catch-all wrapper:
- `Sandesh backend/api/[...path].js`

When deploying to Vercel as serverless functions, make sure requests to `/api/*` hit that wrapper.

