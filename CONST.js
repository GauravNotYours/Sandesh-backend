// Put your secrets/connection strings here (as requested).
// For security, prefer using real environment variables in production.

module.exports = {
  PORT: process.env.PORT ? Number(process.env.PORT) : 3001,
  MONGODB_URI:
    process.env.MONGODB_URI || 'PASTE_MONGODB_CONNECTION_STRING_HERE',
  JWT_SECRET: process.env.JWT_SECRET || 'CHANGE_ME_JWT_SECRET',

  ADMIN_USERNAME: process.env.ADMIN_USERNAME || 'Viparyas',
  ADMIN_PASSWORD:
    process.env.ADMIN_PASSWORD || 'password',

  // For cross-site frontend/backend (Vercel different domains/accounts),
  // set this to your frontend origin, e.g. "https://your-frontend.vercel.app".
  CORS_ORIGIN: process.env.CORS_ORIGIN || '*',

  MESSAGE_LIMIT: process.env.MESSAGE_LIMIT
    ? Number(process.env.MESSAGE_LIMIT)
    : 100,

  MAX_TEXT_LENGTH: process.env.MAX_TEXT_LENGTH
    ? Number(process.env.MAX_TEXT_LENGTH)
    : 600,

  BCRYPT_ROUNDS: process.env.BCRYPT_ROUNDS
    ? Number(process.env.BCRYPT_ROUNDS)
    : 12,

  // Telegram terminal-log bot. Keep both values unset to disable this feature.
  TELEGRAM_BOT_TOKEN: process.env.TELEGRAM_BOT_TOKEN || '',
  // Comma-separated numeric Telegram user IDs permitted to use /startlog and /stoplog.
  TELEGRAM_LOG_ALLOWED_USER_IDS: process.env.TELEGRAM_LOG_ALLOWED_USER_IDS || '',
};
