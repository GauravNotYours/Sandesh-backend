const express = require('express')
const cors = require('cors')
const helmet = require('helmet')
const rateLimit = require('express-rate-limit')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const morgan = require('morgan')
const xss = require('xss')
const dotenv = require('dotenv')
const path = require('path')
const http = require('http')
const { Server } = require('socket.io')
const { body, validationResult } = require('express-validator')

const app = express()
const isProduction = process.env.NODE_ENV === 'production'
const mongoBootstrapState = global.__sandeshMongoBootstrap || {
  seededAdmin: false,
  promise: null,
}

global.__sandeshMongoBootstrap = mongoBootstrapState

// Socket.io instance (only created when running the backend as a persistent server).
let ioInstance = null

// Track connected sockets by userId so we can disconnect banned users.
const socketsByUserId = new Map()

// Load env values from the file named exactly `CONST` (as requested),
// plus standard `.env` (if present).
dotenv.config({ path: path.join(__dirname, '.env') })
try {
  dotenv.config({ path: path.join(__dirname, 'CONST') })
  // Also support `CONST.txt` if that's what you edited.
  dotenv.config({ path: path.join(__dirname, 'CONST.txt') })
} catch {
  // If the file doesn't exist, ignore.
}

// Load CONST after dotenv so values like MONGODB_URI/JWT_SECRET are available.
const CONST = require('./CONST')

function parseAllowedOrigins(value) {
  const raw = String(value || '').trim()
  if (!raw || raw === '*') return ['*']

  return Array.from(
    new Set(
      raw
        .split(',')
        .map((item) => {
          const normalized = String(item || '').trim()
          if (!normalized || normalized === '*') return normalized

          try {
            return new URL(normalized).origin
          } catch {
            return normalized.replace(/\/+$/, '')
          }
        })
        .filter(Boolean),
    ),
  )
}

function isMissingOrPlaceholder(value, placeholders = []) {
  const normalized = String(value || '').trim()
  if (!normalized) return true

  return placeholders.some((placeholder) => normalized === placeholder)
}

function validateRuntimeConfig() {
  if (!isProduction) return

  const invalidKeys = []

  if (
    isMissingOrPlaceholder(CONST.MONGODB_URI, ['PASTE_MONGODB_CONNECTION_STRING_HERE'])
  ) {
    invalidKeys.push('MONGODB_URI')
  }

  if (isMissingOrPlaceholder(CONST.JWT_SECRET, ['CHANGE_ME_JWT_SECRET'])) {
    invalidKeys.push('JWT_SECRET')
  }

  if (parseAllowedOrigins(CONST.CORS_ORIGIN).includes('*')) {
    invalidKeys.push('CORS_ORIGIN')
  }

  if (invalidKeys.length) {
    throw new Error(
      `Invalid production configuration. Set secure values for: ${invalidKeys.join(', ')}`,
    )
  }
}

validateRuntimeConfig()
const allowedCorsOrigins = parseAllowedOrigins(CONST.CORS_ORIGIN)

// --------- Basic security headers / hardening ----------
app.disable('x-powered-by')
app.set('trust proxy', 1)
app.use(
  helmet({
    // Vercel/serverless + dynamic origins can make CSP tricky.
    contentSecurityPolicy: false,
  }),
)
app.use(express.json({ limit: '200kb' }))
app.use(
  morgan('dev', {
    skip: (req, res) => req.method === 'OPTIONS' || res.statusCode === 304,
  }),
)

// --------- CORS (frontend/back can be on different domains) ----------
const allowAnyOrigin = allowedCorsOrigins.includes('*')
const corsOptions = {
  origin:
    allowAnyOrigin
      ? true
      : (origin, callback) => {
          // Allow non-browser clients (no Origin header)
          if (!origin) return callback(null, true)

          const normalizedOrigin = (() => {
            try {
              return new URL(String(origin)).origin
            } catch {
              return String(origin).replace(/\/+$/, '')
            }
          })()

          if (allowedCorsOrigins.includes(normalizedOrigin)) {
            return callback(null, true)
          }

          return callback(new Error('Not allowed by CORS'), false)
        },
  credentials: false,
  methods: ['GET', 'HEAD', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type'],
}
app.use(cors(corsOptions))
app.options('*', cors(corsOptions))

// --------- MongoDB ----------
mongoose.set('strictQuery', true)
mongoose.set('bufferCommands', false)

const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true },
    usernameLower: { type: String, required: true, unique: true, index: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user'], default: 'user' },
    isBanned: { type: Boolean, default: false },
    bannedAt: { type: Date, default: null },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
)

const chatMessageSchema = new mongoose.Schema(
  {
    text: {
      type: String,
      required() {
        return !this.isDeleted
      },
      maxlength: CONST.MAX_TEXT_LENGTH || 600,
      default: '',
    },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    senderUsername: { type: String, required: true },
    isDeleted: { type: Boolean, default: false },
    deletedAt: { type: Date, default: null },
    deletedByUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    replyToMessageId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'ChatMessage',
      default: null,
    },
    replyToText: { type: String, default: null, maxlength: 180 },
    replyToSenderUsername: { type: String, default: null },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
)

chatMessageSchema.index({ createdAt: 1 })
chatMessageSchema.index({ deletedAt: 1 })

const User = mongoose.models.User || mongoose.model('User', userSchema)
const ChatMessage =
  mongoose.models.ChatMessage || mongoose.model('ChatMessage', chatMessageSchema)

async function seedAdmin() {
  const adminUsername = String(CONST.ADMIN_USERNAME || '').trim()
  if (!adminUsername) return

  const existing = await User.findOne({ usernameLower: adminUsername.toLowerCase() })
  if (existing) return

  const adminPassword = String(CONST.ADMIN_PASSWORD || '')
  const hasUnsafeAdminPassword =
    !adminPassword ||
    adminPassword.includes('CHANGE_ME') ||
    adminPassword === 'password'

  if (hasUnsafeAdminPassword && isProduction) {
    throw new Error('ADMIN_PASSWORD must be set to a secure value before seeding the admin user')
  }

  if (hasUnsafeAdminPassword) {
    // Still seed in development so the server runs, but warn heavily.
    console.warn(
      'WARNING: ADMIN_PASSWORD is not set (still using placeholder). Please update CONST.js env vars before production.',
    )
  }

  const passwordHash = await bcrypt.hash(adminPassword, CONST.BCRYPT_ROUNDS)
  await User.create({
    username: adminUsername,
    usernameLower: adminUsername.toLowerCase(),
    passwordHash,
    role: 'admin',
    isBanned: false,
  })
}

async function trimMessagesToLimit() {
  const limit = CONST.MESSAGE_LIMIT || 100
  const count = await ChatMessage.countDocuments()
  if (count <= limit) return

  const excess = count - limit
  const toDelete = await ChatMessage.find()
    .sort({ createdAt: 1 })
    .limit(excess)
    .select('_id')
    .lean()

  if (!toDelete.length) return
  const ids = toDelete.map((d) => d._id)
  await ChatMessage.deleteMany({ _id: { $in: ids } })
}

function pickUserSummary(u) {
  return {
    id: u._id.toString(),
    username: u.username,
    role: u.role,
    isBanned: !!u.isBanned,
  }
}

function formatAdminUser(u) {
  return {
    id: u._id.toString(),
    username: u.username,
    role: u.role,
    isBanned: !!u.isBanned,
    bannedAt: u.bannedAt || null,
    createdAt: u.createdAt || null,
  }
}

function asyncHandler(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next)
  }
}

const ensureDbReady = asyncHandler(async (req, res, next) => {
  try {
    await initDb()
    return next()
  } catch (err) {
    err.status = 503
    err.safeMessage = 'Database unavailable'
    throw err
  }
})

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || ''
  const m = auth.match(/^Bearer\s+(.+)$/i)
  if (!m) return res.status(401).json({ message: 'Missing token' })

  try {
    const payload = jwt.verify(m[1], CONST.JWT_SECRET)
    req.auth = payload
    return next()
  } catch {
    return res.status(401).json({ message: 'Invalid token' })
  }
}

const loadUserMiddleware = asyncHandler(async (req, res, next) => {
  try {
    const userId = req.auth?.sub
    const u = await User.findById(userId).select('_id username role isBanned').lean()
    if (!u) return res.status(401).json({ message: 'User not found' })
    req.user = u
    if (u.isBanned) {
      return res.status(403).json({ code: 'BANNED', message: 'You are banned' })
    }
    return next()
  } catch {
    return res.status(401).json({ message: 'Auth failed' })
  }
})

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ message: 'Admin only' })
  return next()
}

function sanitizeText(input) {
  const s = String(input ?? '')
  // Remove any HTML/JS. Messages are text-only.
  return xss(s, { whiteList: [] }).trim().replace(/\s+/g, ' ')
}

function formatChatMessage(m, extras = {}) {
  const isDeleted = !!m.isDeleted
  return {
    id: m._id.toString(),
    text: isDeleted ? '' : m.text,
    senderId: m.senderId ? m.senderId.toString() : null,
    senderUsername: m.senderUsername,
    isDeleted,
    deletedAt: m.deletedAt || null,
    replyToMessageId: m.replyToMessageId ? m.replyToMessageId.toString() : null,
    replyToText: m.replyToText,
    replyToSenderUsername: m.replyToSenderUsername,
    createdAt: m.createdAt,
    clientRequestId: extras.clientRequestId || null,
  }
}

function normalizeClientRequestId(value) {
  const normalized = String(value || '').trim()
  return normalized ? normalized.slice(0, 64) : null
}

async function createMessageFromPayload({ user, text, replyToId }) {
  const MAX = CONST.MAX_TEXT_LENGTH || 600
  if (!user?.id) throw new Error('Unauthorized')

  const t = sanitizeText(text)
  if (!t || t.length < 1 || t.length > MAX) {
    const err = new Error('Text is required')
    err.status = 400
    throw err
  }

  let replyTo = null
  if (replyToId) {
    replyTo = await ChatMessage.findById(replyToId).lean()
    if (!replyTo) {
      const err = new Error('Reply message not found')
      err.status = 400
      throw err
    }
  }

  const created = await ChatMessage.create({
    text: t,
    senderId: user._id,
    senderUsername: user.username,
    replyToMessageId: replyTo ? replyTo._id : null,
    replyToText: replyTo ? String(replyTo.text).slice(0, 160) : null,
    replyToSenderUsername: replyTo ? replyTo.senderUsername : null,
  })

  await trimMessagesToLimit()
  return created
}

// --------- Routes ----------
app.get('/api/health', (req, res) =>
  res.json({
    ok: true,
    service: 'sandesh-backend',
    realtimeMode: ioInstance ? 'websocket' : 'polling',
    dbReady: mongoose.connection.readyState === 1,
  }),
)
app.get('/api', (req, res) =>
  res.json({
    ok: true,
    message: 'Sandesh backend is running',
    health: '/api/health',
  }),
)
app.use('/api', ensureDbReady)

// --------- Auth ----------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
})

app.post(
  '/api/auth/login',
  loginLimiter,
  [
    body('username').isString().trim().isLength({ min: 3, max: 30 }),
    body('password').isString().isLength({ min: 6, max: 100 }),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() })
    }

    const usernameLower = req.body.username.trim().toLowerCase()
    const password = String(req.body.password)

    const u = await User.findOne({ usernameLower })
    if (!u) return res.status(401).json({ message: 'Invalid username/password' })

    if (u.isBanned) {
      return res.status(403).json({ code: 'BANNED', message: 'You are banned' })
    }

    const ok = await bcrypt.compare(password, u.passwordHash)
    if (!ok) return res.status(401).json({ message: 'Invalid username/password' })

    const token = jwt.sign(
      { sub: u._id.toString(), role: u.role },
      CONST.JWT_SECRET,
      { expiresIn: '7d' },
    )

    return res.json({ token, user: pickUserSummary(u) })
  }),
)

app.get('/api/auth/me', authMiddleware, loadUserMiddleware, (req, res) => {
  return res.json({ user: pickUserSummary(req.user) })
})

// --------- Admin ----------
app.get(
  '/api/admin/users',
  authMiddleware,
  loadUserMiddleware,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const users = await User.find()
      .select('_id username usernameLower role isBanned bannedAt createdAt')
      .sort({ createdAt: -1 })
      .lean()

    return res.json({
      users: users.map((u) => formatAdminUser(u)),
    })
  }),
)

app.post(
  '/api/admin/create-user',
  authMiddleware,
  loadUserMiddleware,
  requireAdmin,
  [
    body('username').isString().trim().isLength({ min: 3, max: 30 }),
    body('password').isString().isLength({ min: 6, max: 100 }),
    body('role').optional().isIn(['admin', 'user']),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() })

    const requestedUsername = req.body.username.trim()
    const usernameLower = requestedUsername.toLowerCase()
    const requestedRole = req.body.role === 'admin' ? 'admin' : 'user'

    // Per requirement: admin name is "Viparyas".
    const onlyViparyasCanBeAdmin =
      usernameLower === String(CONST.ADMIN_USERNAME || 'Viparyas').trim().toLowerCase()

    const role = requestedRole === 'admin' ? (onlyViparyasCanBeAdmin ? 'admin' : 'user') : 'user'

    if (requestedRole === 'admin' && role !== 'admin') {
      return res.status(400).json({ message: 'Only Viparyas can be admin' })
    }

    const existing = await User.findOne({ usernameLower })
    if (existing) return res.status(409).json({ message: 'Username already exists' })

    const passwordHash = await bcrypt.hash(req.body.password, CONST.BCRYPT_ROUNDS)
    const created = await User.create({
      username: requestedUsername,
      usernameLower,
      passwordHash,
      role,
      isBanned: false,
    })

    return res.json({
      ok: true,
      message: `User "${created.username}" created successfully`,
      user: formatAdminUser(created),
    })
  }),
)

app.post(
  '/api/admin/ban-user',
  authMiddleware,
  loadUserMiddleware,
  requireAdmin,
  [
    body('userId').isString().isLength({ min: 10 }),
    body('banned').isBoolean(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() })

    const { userId, banned } = req.body

    const viparyasUser = await User.findOne({
      usernameLower: String(CONST.ADMIN_USERNAME || 'Viparyas').trim().toLowerCase(),
    })

    if (viparyasUser && viparyasUser._id.toString() === String(userId)) {
      return res.status(400).json({ message: 'Cannot ban Viparyas' })
    }

    const u = await User.findById(userId)
    if (!u) return res.status(404).json({ message: 'User not found' })

    u.isBanned = banned
    u.bannedAt = banned ? new Date() : null
    await u.save()

    // If running as a persistent server, immediately disconnect banned sockets.
    if (ioInstance && banned) {
      const userKey = String(userId)
      const socketIdSet = socketsByUserId.get(userKey)
      if (socketIdSet && socketIdSet.size) {
        for (const sid of socketIdSet) {
          ioInstance.sockets.sockets.get(sid)?.disconnect(true)
        }
      }
    }

    return res.json({
      ok: true,
      message: `User "${u.username}" ${banned ? 'banned' : 'unbanned'} successfully`,
      user: formatAdminUser(u),
    })
  }),
)

app.delete(
  '/api/admin/users/:id',
  authMiddleware,
  loadUserMiddleware,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const userId = req.params.id

    const viparyasUser = await User.findOne({
      usernameLower: String(CONST.ADMIN_USERNAME || 'Viparyas').trim().toLowerCase(),
    })

    if (viparyasUser && viparyasUser._id.toString() === String(userId)) {
      return res.status(400).json({ message: 'Cannot delete Viparyas' })
    }

    const u = await User.findById(userId)
    if (!u) return res.status(404).json({ message: 'User not found' })

    if (ioInstance) {
      const socketIdSet = socketsByUserId.get(String(userId))
      if (socketIdSet?.size) {
        for (const sid of socketIdSet) {
          ioInstance.sockets.sockets.get(sid)?.disconnect(true)
        }
      }
    }

    await u.deleteOne()
    return res.json({
      ok: true,
      message: `User "${u.username}" deleted successfully`,
      userId: String(userId),
      username: u.username,
    })
  }),
)

app.post(
  '/api/admin/reset-password',
  authMiddleware,
  loadUserMiddleware,
  requireAdmin,
  [
    body('userId').isString().isLength({ min: 10 }),
    body('newPassword').isString().isLength({ min: 6, max: 100 }),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() })

    const { userId, newPassword } = req.body

    const viparyasUser = await User.findOne({
      usernameLower: String(CONST.ADMIN_USERNAME || 'Viparyas').trim().toLowerCase(),
    })
    if (viparyasUser && viparyasUser._id.toString() === String(userId)) {
      return res.status(400).json({ message: 'Use ADMIN_PASSWORD to change Viparyas password' })
    }

    const u = await User.findById(userId)
    if (!u) return res.status(404).json({ message: 'User not found' })

    u.passwordHash = await bcrypt.hash(String(newPassword), CONST.BCRYPT_ROUNDS)
    await u.save()

    return res.json({
      ok: true,
      message: `Password reset for "${u.username}" completed successfully`,
      user: formatAdminUser(u),
    })
  }),
)

// --------- Chat (text-only) ----------
app.get(
  '/api/chat/messages',
  authMiddleware,
  loadUserMiddleware,
  asyncHandler(async (req, res) => {
    const limit = CONST.MESSAGE_LIMIT || 100
    const sinceRaw = req.query.since

    let sinceDate = null
    if (typeof sinceRaw !== 'undefined') {
      const sinceNum = Number(sinceRaw)
      if (Number.isFinite(sinceNum) && sinceNum > 0) {
        sinceDate = new Date(sinceNum)
      } else {
        const d = new Date(String(sinceRaw))
        if (!Number.isNaN(d.getTime())) sinceDate = d
      }
    }

    const filter = sinceDate
      ? {
          $or: [{ createdAt: { $gt: sinceDate } }, { deletedAt: { $gt: sinceDate } }],
        }
      : {}
    const messagesDesc = await ChatMessage.find(filter)
      .select(
        '_id text senderId senderUsername isDeleted deletedAt replyToMessageId replyToText replyToSenderUsername createdAt',
      )
      .sort({ createdAt: -1 }) // newest -> oldest (we reverse below)
      .limit(limit)
      .lean()

    const messages = messagesDesc.reverse()

    return res.json({
      messages: messages.map((m) => formatChatMessage(m)),
    })
  }),
)

app.post(
  '/api/chat/messages',
  authMiddleware,
  loadUserMiddleware,
  [
    body('text').isString().isLength({ min: 1, max: CONST.MAX_TEXT_LENGTH || 600 }),
    body('replyToId').optional().isString().isLength({ min: 10 }),
    body('clientRequestId').optional().isString().isLength({ min: 1, max: 64 }),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() })

    const text = sanitizeText(req.body.text)
    if (!text) return res.status(400).json({ message: 'Text is required' })

    const clientRequestId = normalizeClientRequestId(req.body.clientRequestId)
    const replyToIdRaw = req.body.replyToId
    let replyTo = null
    if (replyToIdRaw) {
      replyTo = await ChatMessage.findById(replyToIdRaw).lean()
      if (!replyTo) return res.status(400).json({ message: 'Reply message not found' })
    }

    const created = await ChatMessage.create({
      text,
      senderId: req.user._id,
      senderUsername: req.user.username,
      replyToMessageId: replyTo ? replyTo._id : null,
      replyToText: replyTo ? String(replyTo.text).slice(0, 160) : null,
      replyToSenderUsername: replyTo ? replyTo.senderUsername : null,
    })

    await trimMessagesToLimit()

    const formattedMessage = formatChatMessage(created, { clientRequestId })

    // Real-time: broadcast to all connected websocket clients (persistent server mode).
    if (ioInstance) {
      ioInstance.emit('chat:newMessage', formattedMessage)
    }

    return res.json({ message: formattedMessage })
  }),
)

app.delete(
  '/api/chat/messages/:id',
  authMiddleware,
  loadUserMiddleware,
  asyncHandler(async (req, res) => {
    const messageId = req.params.id
    const msg = await ChatMessage.findById(messageId)
    if (!msg) return res.status(404).json({ message: 'Message not found' })

    const isOwner = msg.senderId.toString() === req.user._id.toString()
    const isAdmin = req.user.role === 'admin'
    if (!isOwner && !isAdmin) {
      return res.status(403).json({ message: 'Not allowed' })
    }

    if (!msg.isDeleted) {
      msg.isDeleted = true
      msg.deletedAt = new Date()
      msg.deletedByUserId = req.user._id
      msg.text = ''
      await msg.save()
    }

    const payload = {
      id: msg._id.toString(),
      isDeleted: true,
      deletedAt: msg.deletedAt,
      senderUsername: msg.senderUsername,
    }

    if (ioInstance) ioInstance.emit('chat:deleted', payload)
    return res.json({ ok: true, message: payload })
  }),
)

app.use('/api', (req, res) => {
  return res.status(404).json({ message: 'Route not found' })
})

app.use((err, req, res, next) => {
  const status = Number(err?.status) || 500
  const code = err?.code
  const safeMessage =
    err?.safeMessage ||
    (status < 500 ? err?.message || 'Request failed' : 'Internal server error')

  if (status >= 500) {
    // eslint-disable-next-line no-console
    console.error(err)
  }

  return res.status(status).json({
    message: safeMessage,
    ...(code ? { code } : {}),
  })
})

// --------- Bootstrap ----------
async function initDb() {
  if (mongoose.connection.readyState === 1) {
    if (!mongoBootstrapState.seededAdmin) {
      await seedAdmin()
      mongoBootstrapState.seededAdmin = true
    }
    return true
  }

  if (mongoBootstrapState.promise) {
    return mongoBootstrapState.promise
  }

  mongoBootstrapState.promise = (async () => {
    try {
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(CONST.MONGODB_URI, {
          serverSelectionTimeoutMS: Number(
            process.env.MONGODB_SERVER_SELECTION_TIMEOUT_MS || 10000,
          ),
          socketTimeoutMS: Number(process.env.MONGODB_SOCKET_TIMEOUT_MS || 20000),
          maxPoolSize: Number(process.env.MONGODB_MAX_POOL_SIZE || 10),
        })
      } else if (mongoose.connection.readyState === 3) {
        // If a previous attempt is still disconnecting, wait for it to settle.
        await new Promise((resolve) => {
          mongoose.connection.once('disconnected', resolve)
        })
        await mongoose.connect(CONST.MONGODB_URI, {
          serverSelectionTimeoutMS: Number(
            process.env.MONGODB_SERVER_SELECTION_TIMEOUT_MS || 10000,
          ),
          socketTimeoutMS: Number(process.env.MONGODB_SOCKET_TIMEOUT_MS || 20000),
          maxPoolSize: Number(process.env.MONGODB_MAX_POOL_SIZE || 10),
        })
      }

      if (!mongoBootstrapState.seededAdmin) {
        await seedAdmin()
        mongoBootstrapState.seededAdmin = true
      }

      return true
    } catch (err) {
      mongoBootstrapState.promise = null
      mongoBootstrapState.seededAdmin = false

      if (mongoose.connection.readyState !== 0) {
        try {
          await mongoose.disconnect()
        } catch {
          // ignore cleanup failures
        }
      }

      throw err
    }
  })()

  return mongoBootstrapState.promise
}

// Eagerly start DB init so serverless handlers (that import this module)
// can immediately use the models.
initDb().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('Mongo init failed:', err?.message || err)
})

if (require.main === module) {
  initDb()
    .then(() => {
      const server = http.createServer(app)
      const io = new Server(server, {
        cors: {
          origin: allowAnyOrigin ? '*' : allowedCorsOrigins,
          methods: ['GET', 'POST'],
        },
      })

      ioInstance = io

      // Authenticate websocket connections using JWT.
      io.use(async (socket, next) => {
        try {
          const token =
            socket.handshake.auth?.token ||
            socket.handshake.query?.token ||
            socket.handshake.headers?.authorization ||
            ''

          const normalized =
            String(token).startsWith('Bearer ') ? String(token).slice(7) : String(token)

          if (!normalized) {
            const err = new Error('Missing token')
            err.status = 401
            return next(err)
          }

          const payload = jwt.verify(normalized, CONST.JWT_SECRET)
          const u = await User.findById(payload.sub).select('username role isBanned bannedAt')

          if (!u) {
            const err = new Error('User not found')
            err.status = 401
            return next(err)
          }

          if (u.isBanned) {
            const err = new Error('You are banned')
            err.status = 403
            err.code = 'BANNED'
            return next(err)
          }

          socket.user = {
            _id: u._id,
            id: u._id.toString(),
            username: u.username,
            role: u.role,
          }

          return next()
        } catch {
          const err = new Error('Invalid token')
          err.status = 401
          return next(err)
        }
      })

      io.on('connection', (socket) => {
        const userKey = socket.user.id
        if (!socketsByUserId.has(userKey)) socketsByUserId.set(userKey, new Set())
        socketsByUserId.get(userKey).add(socket.id)

        socket.on('disconnect', () => {
          const set = socketsByUserId.get(userKey)
          if (!set) return
          set.delete(socket.id)
          if (set.size === 0) socketsByUserId.delete(userKey)
        })

        // Optional: allow sending via websocket for real-time feel.
        socket.on('chat:send', async (payload, ack) => {
          try {
            const user = socket.user
            const text = payload?.text
            const replyToId = payload?.replyToId || null
            const clientRequestId = normalizeClientRequestId(payload?.clientRequestId)

            const created = await createMessageFromPayload({
              user,
              text,
              replyToId,
            })
            const formattedMessage = formatChatMessage(created, { clientRequestId })

            // Broadcast to everyone.
            ioInstance.emit('chat:newMessage', formattedMessage)
            if (ack) ack({ ok: true, message: formattedMessage })
          } catch (err) {
            if (ack) ack({ ok: false, message: err?.message || 'Failed to send' })
          }
        })

        socket.on('chat:delete', async (payload, ack) => {
          try {
            const userId = socket.user.id
            const messageId = payload?.messageId
            if (!messageId) {
              if (ack) ack({ ok: false, message: 'Missing messageId' })
              return
            }

            const msg = await ChatMessage.findById(messageId)
            if (!msg) {
              if (ack) ack({ ok: false, message: 'Message not found' })
              return
            }

            const isOwner = msg.senderId.toString() === userId
            const isAdmin = socket.user.role === 'admin'
            if (!isOwner && !isAdmin) {
              if (ack) ack({ ok: false, message: 'Not allowed' })
              return
            }

            if (!msg.isDeleted) {
              msg.isDeleted = true
              msg.deletedAt = new Date()
              msg.deletedByUserId = socket.user._id
              msg.text = ''
              await msg.save()
            }

            const deletedPayload = {
              id: msg._id.toString(),
              isDeleted: true,
              deletedAt: msg.deletedAt,
              senderUsername: msg.senderUsername,
            }

            ioInstance.emit('chat:deleted', deletedPayload)
            if (ack) ack({ ok: true, message: deletedPayload })
          } catch (err) {
            if (ack) ack({ ok: false, message: err?.message || 'Delete failed' })
          }
        })
      })

      server.listen(CONST.PORT, () => {
        // eslint-disable-next-line no-console
        console.log(`Sandesh backend (HTTP+WebSocket) running on port ${CONST.PORT}`)
      })
    })
    .catch((err) => {
      // eslint-disable-next-line no-console
      console.error(err)
      process.exit(1)
    })
}

// Export Express app for wrapping in a serverless handler.
module.exports = app
