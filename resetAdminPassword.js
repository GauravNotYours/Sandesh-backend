/**
 * One-time helper:
 * Resets the seeded admin user's password to whatever is currently in CONST/ENV.
 *
 * Usage:
 *   node resetAdminPassword.js
 */

const bcrypt = require('bcryptjs')
const mongoose = require('mongoose')
const dotenv = require('dotenv')
const path = require('path')

dotenv.config({ path: path.join(__dirname, '.env') })
try {
  dotenv.config({ path: path.join(__dirname, 'CONST') })
  dotenv.config({ path: path.join(__dirname, 'CONST.txt') })
} catch {
  // ignore
}

const CONST = require('./CONST')

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

const User = mongoose.models.User || mongoose.model('User', userSchema)

async function main() {
  if (!CONST.MONGODB_URI || String(CONST.MONGODB_URI).includes('PASTE_MONGODB_CONNECTION_STRING_HERE')) {
    throw new Error('Set MONGODB_URI in Sandesh backend/.env or Sandesh backend/CONST first.')
  }

  const adminUsername = String(CONST.ADMIN_USERNAME || '').trim()
  if (!adminUsername) throw new Error('ADMIN_USERNAME is empty')

  const newPassword = String(CONST.ADMIN_PASSWORD || '')
  if (!newPassword) throw new Error('ADMIN_PASSWORD is empty')

  await mongoose.connect(CONST.MONGODB_URI)

  const usernameLower = adminUsername.toLowerCase()
  const u = await User.findOne({ usernameLower })

  const passwordHash = await bcrypt.hash(newPassword, CONST.BCRYPT_ROUNDS)

  if (u) {
    u.passwordHash = passwordHash
    u.role = 'admin'
    u.isBanned = false
    u.bannedAt = null
    await u.save()
  } else {
    await User.create({
      username: adminUsername,
      usernameLower,
      passwordHash,
      role: 'admin',
      isBanned: false,
    })
  }

  // eslint-disable-next-line no-console
  console.log(`Admin password reset for "${adminUsername}" to current ADMIN_PASSWORD.`)
  await mongoose.disconnect()
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err?.message || err)
  process.exit(1)
})

