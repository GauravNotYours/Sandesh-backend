const express = require('express')
const cors = require('cors')
const helmet = require('helmet')
const rateLimit = require('express-rate-limit')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const morgan = require('morgan')
const dotenv = require('dotenv')
const path = require('path')
const http = require('http')
const { Server } = require('socket.io')
const { body, validationResult } = require('express-validator')
const { startTelegramTerminalLogger } = require('./telegramTerminalLogger')

const app = express()
const isProduction = process.env.NODE_ENV === 'production'
const mongoBootstrapState = global.__sandeshMongoBootstrap || {
  seededAdmin: false,
  promise: null,
}
const messageTrimState = global.__sandeshMessageTrim || {
  timer: null,
  running: false,
  rerunRequested: false,
}

global.__sandeshMongoBootstrap = mongoBootstrapState
global.__sandeshMessageTrim = messageTrimState

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
    conversationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Conversation',
      default: null,
    },
    text: {
      type: String,
      required() {
        return !this.isDeleted
      },
      maxlength: Math.ceil(((CONST.MAX_TEXT_LENGTH || 600) * 4 + 16) / 3) * 4 + 25,
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
chatMessageSchema.index({ conversationId: 1, createdAt: -1 })

const conversationSchema = new mongoose.Schema(
  {
    participants: [
      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    ],
    participantKey: { type: String, required: true, unique: true, index: true },
    lastMessageAt: { type: Date, default: null },
    encryptionKeyId: { type: String, default: null },
  },
  { timestamps: true },
)

conversationSchema.index({ participants: 1, lastMessageAt: -1 })

const User = mongoose.models.User || mongoose.model('User', userSchema)
const ChatMessage =
  mongoose.models.ChatMessage || mongoose.model('ChatMessage', chatMessageSchema)
const Conversation =
  mongoose.models.Conversation || mongoose.model('Conversation', conversationSchema)

const cryptoDeviceSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    deviceId: { type: String, required: true },
    publicKeyJwk: { type: mongoose.Schema.Types.Mixed, required: true },
    status: { type: String, enum: ['pending', 'approved'], required: true },
    approvedAt: { type: Date, default: null },
  },
  { timestamps: { createdAt: true, updatedAt: true } },
)

cryptoDeviceSchema.index({ userId: 1, deviceId: 1 }, { unique: true })

const conversationKeyEnvelopeSchema = new mongoose.Schema(
  {
    conversationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Conversation',
      required: true,
    },
    deviceId: { type: String, required: true },
    keyId: { type: String, required: true },
    ephemeralPublicKeyJwk: { type: mongoose.Schema.Types.Mixed, required: true },
    iv: { type: String, required: true, maxlength: 64 },
    ciphertext: { type: String, required: true, maxlength: 1024 },
  },
  { timestamps: true },
)

conversationKeyEnvelopeSchema.index(
  { conversationId: 1, deviceId: 1 },
  { unique: true },
)

const CryptoDevice =
  mongoose.models.CryptoDevice || mongoose.model('CryptoDevice', cryptoDeviceSchema)
const ConversationKeyEnvelope =
  mongoose.models.ConversationKeyEnvelope ||
  mongoose.model('ConversationKeyEnvelope', conversationKeyEnvelopeSchema)

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
  const conversations = await ChatMessage.aggregate([
    { $match: { conversationId: { $type: 'objectId' } } },
    { $group: { _id: '$conversationId', count: { $sum: 1 } } },
    { $match: { count: { $gt: limit } } },
  ])

  for (const conversation of conversations) {
    const toDelete = await ChatMessage.find({ conversationId: conversation._id })
      .sort({ createdAt: 1 })
      .limit(conversation.count - limit)
      .select('_id')
      .lean()
    if (toDelete.length) {
      await ChatMessage.deleteMany({ _id: { $in: toDelete.map((message) => message._id) } })
    }
  }

  const legacyCount = await ChatMessage.countDocuments({ conversationId: null })
  if (legacyCount <= limit) return

  const legacyMessagesToDelete = await ChatMessage.find({ conversationId: null })
    .sort({ createdAt: 1 })
    .limit(legacyCount - limit)
    .select('_id')
    .lean()
  if (legacyMessagesToDelete.length) {
    await ChatMessage.deleteMany({
      _id: { $in: legacyMessagesToDelete.map((message) => message._id) },
    })
  }
}

function runTrimMessagesToLimit() {
  if (messageTrimState.running) {
    messageTrimState.rerunRequested = true
    return
  }

  messageTrimState.running = true

  Promise.resolve()
    .then(() => trimMessagesToLimit())
    .catch((err) => {
      // eslint-disable-next-line no-console
      console.error('Message trim failed:', err?.message || err)
    })
    .finally(() => {
      messageTrimState.running = false

      if (messageTrimState.rerunRequested) {
        messageTrimState.rerunRequested = false
        scheduleTrimMessagesToLimit(250)
      }
    })
}

function scheduleTrimMessagesToLimit(delayMs = 400) {
  if (messageTrimState.timer) return

  messageTrimState.timer = setTimeout(() => {
    messageTrimState.timer = null
    runTrimMessagesToLimit()
  }, delayMs)

  if (typeof messageTrimState.timer?.unref === 'function') {
    messageTrimState.timer.unref()
  }
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

function formatChatMessage(m, extras = {}) {
  const isDeleted = !!m.isDeleted
  return {
    id: m._id.toString(),
    conversationId: m.conversationId ? m.conversationId.toString() : null,
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

function getConversationRoom(conversationId) {
  return `conversation:${conversationId}`
}

function getUserRoom(userId) {
  return `user:${userId}`
}

function isValidPublicKeyJwk(value) {
  return (
    value &&
    value.kty === 'EC' &&
    value.crv === 'P-256' &&
    typeof value.x === 'string' &&
    /^[A-Za-z0-9_-]{43}$/.test(value.x) &&
    typeof value.y === 'string' &&
    /^[A-Za-z0-9_-]{43}$/.test(value.y)
  )
}

function isValidEncryptedMessage(value) {
  const maximumLength =
    Math.ceil(((CONST.MAX_TEXT_LENGTH || 600) * 4 + 16) / 3) * 4 + 25
  return (
    typeof value === 'string' &&
    value.length <= maximumLength &&
    /^e2ee:v1:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]{20,3224}$/.test(value)
  )
}

function formatCryptoDevice(device) {
  return {
    userId: device.userId.toString(),
    deviceId: device.deviceId,
    publicKeyJwk: device.publicKeyJwk,
    status: device.status,
    createdAt: device.createdAt,
  }
}

async function emitToConversationParticipants(conversationId, eventName, payload) {
  if (!ioInstance) return

  const conversation = await Conversation.findById(conversationId).select('participants').lean()
  if (!conversation) return

  const rooms = conversation.participants.map((participantId) =>
    getUserRoom(participantId.toString()),
  )
  ioInstance.to(rooms).emit(eventName, payload)
}

function getParticipantKey(firstId, secondId) {
  return [String(firstId), String(secondId)].sort().join(':')
}

async function findConversationForUser(conversationId, userId) {
  if (!mongoose.isValidObjectId(conversationId)) return null
  return Conversation.findOne({
    _id: conversationId,
    participants: userId,
  }).lean()
}

function formatConversation(conversation, otherUser, lastMessage) {
  return {
    id: conversation._id.toString(),
    otherUser: {
      id: otherUser._id.toString(),
      username: otherUser.username,
    },
    lastMessage: lastMessage ? formatChatMessage(lastMessage) : null,
    lastMessageAt: conversation.lastMessageAt || lastMessage?.createdAt || conversation.updatedAt,
    createdAt: conversation.createdAt,
  }
}

async function listConversationsForUser(userId) {
  const conversations = await Conversation.find({ participants: userId })
    .sort({ lastMessageAt: -1, updatedAt: -1 })
    .lean()

  if (!conversations.length) return []

  const otherUserIds = conversations
    .map((conversation) =>
      conversation.participants.find(
        (participantId) => participantId.toString() !== String(userId),
      ),
    )
    .filter(Boolean)
  const users = await User.find({ _id: { $in: otherUserIds } })
    .select('_id username')
    .lean()
  const usersById = new Map(users.map((otherUser) => [otherUser._id.toString(), otherUser]))
  const conversationIds = conversations.map((conversation) => conversation._id)
  const latestMessages = await ChatMessage.aggregate([
    { $match: { conversationId: { $in: conversationIds } } },
    { $sort: { createdAt: -1 } },
    { $group: { _id: '$conversationId', message: { $first: '$$ROOT' } } },
  ])
  const latestMessagesByConversationId = new Map(
    latestMessages.map((result) => [result._id.toString(), result.message]),
  )

  return conversations
    .map((conversation) => {
      const otherUserId = conversation.participants
        .find((participantId) => participantId.toString() !== String(userId))
        ?.toString()
      const otherUser = usersById.get(otherUserId)
      if (!otherUser) return null
      return formatConversation(
        conversation,
        otherUser,
        latestMessagesByConversationId.get(conversation._id.toString()),
      )
    })
    .filter(Boolean)
}

function normalizeClientRequestId(value) {
  const normalized = String(value || '').trim()
  return normalized ? normalized.slice(0, 64) : null
}

async function createMessageFromPayload({ user, text, replyToId, conversationId }) {
  if (!user?.id) {
    const err = new Error('Unauthorized')
    err.status = 401
    throw err
  }
  if (!conversationId) {
    const err = new Error('Conversation not found')
    err.status = 404
    throw err
  }

  const conversation = await findConversationForUser(conversationId, user.id)
  if (!conversation) {
    const err = new Error('Conversation not found')
    err.status = 404
    throw err
  }

  const t = String(text || '')
  if (!isValidEncryptedMessage(t)) {
    const err = new Error('Messages must be encrypted by a supported client')
    err.status = 400
    throw err
  }

  let replyTo = null
  if (replyToId) {
    if (!mongoose.isValidObjectId(replyToId)) {
      const err = new Error('Reply message not found')
      err.status = 400
      throw err
    }
    replyTo = await ChatMessage.findOne({ _id: replyToId, conversationId }).lean()
    if (!replyTo) {
      const err = new Error('Reply message not found')
      err.status = 400
      throw err
    }
  }

  const created = await ChatMessage.create({
    conversationId,
    text: t,
    senderId: user._id,
    senderUsername: user.username,
    replyToMessageId: replyTo ? replyTo._id : null,
    replyToText: null,
    replyToSenderUsername: replyTo ? replyTo.senderUsername : null,
  })

  await Conversation.updateOne(
    { _id: conversationId },
    { $set: { lastMessageAt: created.createdAt } },
  )
  scheduleTrimMessagesToLimit()
  return created
}

function createTelegramDeviceApprovalHandlers() {
  async function findAccount(username) {
    const usernameLower = String(username || '').trim().toLowerCase()
    if (!usernameLower) {
      const error = new Error('Username is required')
      error.status = 400
      throw error
    }

    const user = await User.findOne({ usernameLower }).select('_id username').lean()
    if (!user) {
      const error = new Error('Account not found')
      error.status = 404
      throw error
    }
    return user
  }

  return {
    async listPending() {
      const devices = await CryptoDevice.find({ status: 'pending' })
        .select('userId deviceId createdAt')
        .populate('userId', 'username')
        .sort({ createdAt: 1 })
        .lean()
      return devices.map((device) => ({
        username: device.userId?.username || '[deleted account]',
        deviceId: device.deviceId,
        createdAt: device.createdAt,
      }))
    },

    async approve(username, deviceId) {
      const user = await findAccount(username)
      const device = await CryptoDevice.findOne({
        userId: user._id,
        deviceId: String(deviceId || '').toLowerCase(),
        status: 'pending',
      })
      if (!device) return { count: 0, username: user.username }

      device.status = 'approved'
      device.approvedAt = new Date()
      await device.save()
      try {
        const keyReset = await Conversation.updateMany(
          { participants: user._id },
          { $set: { encryptionKeyId: null } },
        )
        return {
          count: 1,
          username: user.username,
          deviceId: device.deviceId,
          conversationCount: keyReset.modifiedCount,
        }
      } catch (error) {
        try {
          device.status = 'pending'
          device.approvedAt = null
          await device.save()
        } catch (rollbackError) {
          error.rollbackError = rollbackError
        }
        throw error
      }
    },

    async reject(username, deviceId) {
      const user = await findAccount(username)
      const result = await CryptoDevice.deleteOne({
        userId: user._id,
        deviceId: String(deviceId || '').toLowerCase(),
        status: 'pending',
      })
      return {
        count: result.deletedCount,
        username: user.username,
        deviceId: String(deviceId || '').toLowerCase(),
      }
    },
  }
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
  '/api/chat/conversations',
  authMiddleware,
  loadUserMiddleware,
  asyncHandler(async (req, res) => {
    const conversations = await listConversationsForUser(req.user._id)
    return res.json({ conversations })
  }),
)

app.post(
  '/api/chat/conversations',
  authMiddleware,
  loadUserMiddleware,
  [body('username').isString().trim().isLength({ min: 3, max: 30 })],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() })

    const usernameLower = req.body.username.trim().toLowerCase()
    const otherUser = await User.findOne({ usernameLower })
      .select('_id username isBanned')
      .lean()
    if (!otherUser || otherUser.isBanned) {
      return res.status(404).json({ message: 'User not found or unavailable' })
    }

    const userId = req.user._id.toString()
    const otherUserId = otherUser._id.toString()
    if (userId === otherUserId) {
      return res.status(400).json({ message: 'You cannot start a conversation with yourself' })
    }

    const participantKey = getParticipantKey(userId, otherUserId)
    const participants = [userId, otherUserId].sort()
    let conversation
    try {
      conversation = await Conversation.findOneAndUpdate(
        { participantKey },
        { $setOnInsert: { participantKey, participants } },
        { new: true, upsert: true, setDefaultsOnInsert: true },
      ).lean()
    } catch (err) {
      if (err?.code !== 11000) throw err
      conversation = await Conversation.findOne({ participantKey }).lean()
      if (!conversation) throw err
    }

    const lastMessage = await ChatMessage.findOne({ conversationId: conversation._id })
      .sort({ createdAt: -1 })
      .lean()
    return res.json({
      conversation: formatConversation(conversation, otherUser, lastMessage),
    })
  }),
)

app.post(
  '/api/crypto/devices/register',
  authMiddleware,
  loadUserMiddleware,
  [
    body('deviceId').isUUID(),
    body('publicKeyJwk').custom(isValidPublicKeyJwk),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() })

    const deviceId = req.body.deviceId.toLowerCase()
    let device = await CryptoDevice.findOne({
      userId: req.user._id,
      deviceId,
    })
    if (device) {
      if (
        device.publicKeyJwk.x !== req.body.publicKeyJwk.x ||
        device.publicKeyJwk.y !== req.body.publicKeyJwk.y
      ) {
        return res.status(409).json({
          message: 'This device ID is already registered to another encryption key',
          code: 'DEVICE_KEY_MISMATCH',
        })
      }
    } else {
      const hasApprovedDevice = await CryptoDevice.exists({
        userId: req.user._id,
        status: 'approved',
      })
      try {
        device = await CryptoDevice.create({
          userId: req.user._id,
          deviceId,
          publicKeyJwk: req.body.publicKeyJwk,
          status: hasApprovedDevice ? 'pending' : 'approved',
          approvedAt: hasApprovedDevice ? null : new Date(),
        })
      } catch (err) {
        if (err?.code !== 11000) throw err
        device = await CryptoDevice.findOne({ userId: req.user._id, deviceId })
        if (
          !device ||
          device.publicKeyJwk.x !== req.body.publicKeyJwk.x ||
          device.publicKeyJwk.y !== req.body.publicKeyJwk.y
        ) {
          return res.status(409).json({
            message: 'This device ID is already registered to another encryption key',
            code: 'DEVICE_KEY_MISMATCH',
          })
        }
      }
    }

    return res.json({
      device: formatCryptoDevice(device),
      approved: device.status === 'approved',
    })
  }),
)

app.get(
  '/api/crypto/devices/pending',
  authMiddleware,
  loadUserMiddleware,
  asyncHandler(async (req, res) => {
    const devices = await CryptoDevice.find({
      userId: req.user._id,
      status: 'pending',
    })
      .sort({ createdAt: 1 })
      .lean()
    return res.json({
      devices: devices.map((device) => ({
        deviceId: device.deviceId,
        createdAt: device.createdAt,
      })),
    })
  }),
)

app.get(
  '/api/crypto/devices',
  authMiddleware,
  loadUserMiddleware,
  asyncHandler(async (req, res) => {
    const devices = await CryptoDevice.find({ userId: req.user._id })
      .sort({ createdAt: 1 })
      .lean()
    return res.json({
      devices: devices.map((device) => ({
        deviceId: device.deviceId,
        status: device.status,
        createdAt: device.createdAt,
      })),
    })
  }),
)

app.post(
  '/api/crypto/devices/:deviceId/approve',
  authMiddleware,
  loadUserMiddleware,
  [body('sourceDeviceId').isUUID()],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() })

    const targetDevice = await CryptoDevice.findOne({
      userId: req.user._id,
      deviceId: req.params.deviceId.toLowerCase(),
      status: 'pending',
    })
    if (!targetDevice) return res.status(404).json({ message: 'Pending device not found' })

    const sourceDevice = await CryptoDevice.findOne({
      userId: req.user._id,
      deviceId: req.body.sourceDeviceId.toLowerCase(),
      status: 'approved',
    })
    if (!sourceDevice) {
      return res.status(403).json({ message: 'An approved device is required to approve this device' })
    }

    targetDevice.status = 'approved'
    targetDevice.approvedAt = new Date()
    await targetDevice.save()
    return res.json({ device: formatCryptoDevice(targetDevice) })
  }),
)

app.get(
  '/api/chat/conversations/:conversationId/keys',
  authMiddleware,
  loadUserMiddleware,
  asyncHandler(async (req, res) => {
    const { conversationId } = req.params
    const deviceId = String(req.query.deviceId || '').toLowerCase()
    if (!/^[0-9a-f-]{36}$/.test(deviceId)) {
      return res.status(400).json({ message: 'Valid deviceId is required' })
    }

    const conversation = await findConversationForUser(conversationId, req.user._id)
    if (!conversation) return res.status(404).json({ message: 'Conversation not found' })

    const currentDevice = await CryptoDevice.findOne({
      userId: req.user._id,
      deviceId,
      status: 'approved',
    }).lean()
    if (!currentDevice) {
      return res.status(403).json({ message: 'This device is not approved for encryption' })
    }

    const devices = await CryptoDevice.find({
      userId: { $in: conversation.participants },
      status: 'approved',
    })
      .select('userId deviceId publicKeyJwk status createdAt')
      .lean()
    const envelope = await ConversationKeyEnvelope.findOne({
      conversationId: conversation._id,
      deviceId,
    }).lean()
    const envelopeDeviceIds = await ConversationKeyEnvelope.find({
      conversationId: conversation._id,
      keyId: conversation.encryptionKeyId,
    })
      .distinct('deviceId')

    return res.json({
      keyId: conversation.encryptionKeyId || null,
      devices: devices.map(formatCryptoDevice),
      envelopeDeviceIds,
      envelope:
        envelope && envelope.keyId === conversation.encryptionKeyId
          ? {
              keyId: envelope.keyId,
              ephemeralPublicKeyJwk: envelope.ephemeralPublicKeyJwk,
              iv: envelope.iv,
              ciphertext: envelope.ciphertext,
            }
          : null,
    })
  }),
)

app.post(
  '/api/chat/conversations/:conversationId/keys/claim',
  authMiddleware,
  loadUserMiddleware,
  [
    body('deviceId').isUUID(),
    body('keyId').isUUID(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() })

    const conversation = await findConversationForUser(
      req.params.conversationId,
      req.user._id,
    )
    if (!conversation) return res.status(404).json({ message: 'Conversation not found' })

    const device = await CryptoDevice.findOne({
      userId: req.user._id,
      deviceId: req.body.deviceId.toLowerCase(),
      status: 'approved',
    }).lean()
    if (!device) return res.status(403).json({ message: 'This device is not approved' })

    const result = await Conversation.updateOne(
      { _id: conversation._id, encryptionKeyId: null },
      { $set: { encryptionKeyId: req.body.keyId.toLowerCase() } },
    )
    const current = await Conversation.findById(conversation._id)
      .select('encryptionKeyId')
      .lean()
    return res.json({
      keyId: current?.encryptionKeyId || null,
      claimed: result.modifiedCount === 1,
    })
  }),
)

app.post(
  '/api/chat/conversations/:conversationId/keys/envelopes',
  authMiddleware,
  loadUserMiddleware,
  [
    body('sourceDeviceId').isUUID(),
    body('targetDeviceId').isUUID(),
    body('keyId').isUUID(),
    body('ephemeralPublicKeyJwk').custom(isValidPublicKeyJwk),
    body('iv').matches(/^[A-Za-z0-9_-]{16}$/),
    body('ciphertext').matches(/^[A-Za-z0-9_-]{60,100}$/),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() })

    const conversation = await findConversationForUser(
      req.params.conversationId,
      req.user._id,
    )
    if (!conversation) return res.status(404).json({ message: 'Conversation not found' })
    if (conversation.encryptionKeyId !== req.body.keyId.toLowerCase()) {
      return res.status(409).json({ message: 'Conversation encryption key changed' })
    }

    const sourceDevice = await CryptoDevice.findOne({
      userId: req.user._id,
      deviceId: req.body.sourceDeviceId.toLowerCase(),
      status: 'approved',
    }).lean()
    if (!sourceDevice) return res.status(403).json({ message: 'Source device is not approved' })

    const targetDevice = await CryptoDevice.findOne({
      deviceId: req.body.targetDeviceId.toLowerCase(),
      userId: { $in: conversation.participants },
      status: 'approved',
    }).lean()
    if (!targetDevice) return res.status(404).json({ message: 'Approved target device not found' })

    await ConversationKeyEnvelope.findOneAndUpdate(
      {
        conversationId: conversation._id,
        deviceId: targetDevice.deviceId,
      },
      {
        $set: {
          keyId: conversation.encryptionKeyId,
          ephemeralPublicKeyJwk: req.body.ephemeralPublicKeyJwk,
          iv: req.body.iv,
          ciphertext: req.body.ciphertext,
        },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true },
    )
    return res.json({ ok: true })
  }),
)

app.get(
  '/api/chat/conversations/:conversationId/messages',
  authMiddleware,
  loadUserMiddleware,
  asyncHandler(async (req, res) => {
    const conversation = await findConversationForUser(
      req.params.conversationId,
      req.user._id,
    )
    if (!conversation) return res.status(404).json({ message: 'Conversation not found' })

    const limit = CONST.MESSAGE_LIMIT || 100
    const sinceRaw = req.query.since
    let sinceDate = null
    if (typeof sinceRaw !== 'undefined') {
      const sinceNum = Number(sinceRaw)
      if (Number.isFinite(sinceNum) && sinceNum > 0) {
        sinceDate = new Date(sinceNum)
      } else {
        const date = new Date(String(sinceRaw))
        if (!Number.isNaN(date.getTime())) sinceDate = date
      }
    }

    const filter = { conversationId: conversation._id }
    if (sinceDate) {
      filter.$or = [{ createdAt: { $gt: sinceDate } }, { deletedAt: { $gt: sinceDate } }]
    }
    const messagesDesc = await ChatMessage.find(filter)
      .select(
        '_id conversationId text senderId senderUsername isDeleted deletedAt replyToMessageId replyToText replyToSenderUsername createdAt',
      )
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean()

    return res.json({ messages: messagesDesc.reverse().map((message) => formatChatMessage(message)) })
  }),
)

app.post(
  '/api/chat/conversations/:conversationId/messages',
  authMiddleware,
  loadUserMiddleware,
  [
    body('text')
      .isString()
      .isLength({
        min: 1,
        max: Math.ceil(((CONST.MAX_TEXT_LENGTH || 600) * 4 + 16) / 3) * 4 + 25,
      }),
    body('replyToId').optional().isMongoId(),
    body('clientRequestId').optional().isString().isLength({ min: 1, max: 64 }),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() })

    const created = await createMessageFromPayload({
      user: {
        _id: req.user._id,
        id: req.user._id.toString(),
        username: req.user.username,
      },
      text: req.body.text,
      replyToId: req.body.replyToId,
      conversationId: req.params.conversationId,
    })
    const message = formatChatMessage(created, {
      clientRequestId: normalizeClientRequestId(req.body.clientRequestId),
    })
    await emitToConversationParticipants(
      req.params.conversationId,
      'chat:newMessage',
      message,
    )
    return res.json({ message })
  }),
)

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

    const filter = { conversationId: null }
    if (sinceDate) {
      filter.$or = [{ createdAt: { $gt: sinceDate } }, { deletedAt: { $gt: sinceDate } }]
    }
    const messagesDesc = await ChatMessage.find(filter)
      .select(
        '_id conversationId text senderId senderUsername isDeleted deletedAt replyToMessageId replyToText replyToSenderUsername createdAt',
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
  (req, res) => {
    return res.status(410).json({
      message: 'Shared plaintext messaging is disabled. Start a private encrypted conversation.',
    })
  },
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
    if (
      msg.conversationId &&
      !isAdmin &&
      !(await findConversationForUser(msg.conversationId, req.user._id))
    ) {
      return res.status(404).json({ message: 'Message not found' })
    }
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
      conversationId: msg.conversationId ? msg.conversationId.toString() : null,
    }

    if (ioInstance) {
      if (msg.conversationId) {
        await emitToConversationParticipants(
          msg.conversationId.toString(),
          'chat:deleted',
          payload,
        )
      } else {
        ioInstance.emit('chat:deleted', payload)
      }
    }
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

      io.on('connection', async (socket) => {
        const userKey = socket.user.id
        try {
          await socket.join(getUserRoom(userKey))
        } catch (err) {
          console.error('Failed to join authenticated user socket room:', err?.message || err)
          socket.disconnect(true)
          return
        }
        if (!socketsByUserId.has(userKey)) socketsByUserId.set(userKey, new Set())
        socketsByUserId.get(userKey).add(socket.id)

        socket.on('disconnect', () => {
          const set = socketsByUserId.get(userKey)
          if (!set) return
          set.delete(socket.id)
          if (set.size === 0) socketsByUserId.delete(userKey)
        })

        socket.on('chat:join', async (payload, ack) => {
          try {
            const conversationId = String(payload?.conversationId || '')
            const conversation = await findConversationForUser(conversationId, userKey)
            if (!conversation) {
              if (ack) ack({ ok: false, message: 'Conversation not found' })
              return
            }

            await socket.join(getConversationRoom(conversationId))
            if (ack) ack({ ok: true })
          } catch (err) {
            if (ack) ack({ ok: false, message: err?.message || 'Failed to join conversation' })
          }
        })

        socket.on('chat:leave', (payload) => {
          const conversationId = String(payload?.conversationId || '')
          if (mongoose.isValidObjectId(conversationId)) {
            void socket.leave(getConversationRoom(conversationId))
          }
        })

        socket.on('chat:send', async (payload, ack) => {
          try {
            const user = socket.user
            const text = payload?.text
            const replyToId = payload?.replyToId || null
            const conversationId = String(payload?.conversationId || '')
            const clientRequestId = normalizeClientRequestId(payload?.clientRequestId)

            const created = await createMessageFromPayload({
              user,
              text,
              replyToId,
              conversationId,
            })
            const formattedMessage = formatChatMessage(created, { clientRequestId })

            await emitToConversationParticipants(
              conversationId,
              'chat:newMessage',
              formattedMessage,
            )
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
            if (
              msg.conversationId &&
              !isAdmin &&
              !(await findConversationForUser(msg.conversationId, userId))
            ) {
              if (ack) ack({ ok: false, message: 'Message not found' })
              return
            }
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
              conversationId: msg.conversationId ? msg.conversationId.toString() : null,
            }

            if (msg.conversationId) {
              await emitToConversationParticipants(
                msg.conversationId.toString(),
                'chat:deleted',
                deletedPayload,
              )
            } else {
              ioInstance.emit('chat:deleted', deletedPayload)
            }
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

      startTelegramTerminalLogger({
        token: CONST.TELEGRAM_BOT_TOKEN,
        allowedUserIds: CONST.TELEGRAM_LOG_ALLOWED_USER_IDS,
        deviceApproval: createTelegramDeviceApprovalHandlers(),
      })
        .then((telegramTerminalLogger) => {
          if (!telegramTerminalLogger) return
          // eslint-disable-next-line no-console
          console.log('Telegram terminal logger is ready for /startlog commands')
        })
        .catch((err) => {
          // Do not prevent the chat server from starting if Telegram is unavailable.
          // eslint-disable-next-line no-console
          console.error('Telegram terminal logger failed to start:', err?.message || err)
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
