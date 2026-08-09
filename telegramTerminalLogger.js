const { Telegraf } = require('telegraf')

const MAX_TELEGRAM_MESSAGE_LENGTH = 3800
const MAX_BUFFER_LENGTH = 100_000

function normalizeAllowedPrincipal(value) {
  return String(value || '').trim().replace(/^@/, '').toLowerCase()
}

function parseAllowedPrincipals(value) {
  return new Set(
    String(value || '')
      .split(',')
      .map(normalizeAllowedPrincipal)
      .filter(Boolean),
  )
}

function normalizeTerminalOutput(chunk) {
  return String(chunk)
    .replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/(mongodb(?:\+srv)?:\/\/[^:\s/]+:)[^@\s/]+@/gi, '$1[REDACTED]@')
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, '$1[REDACTED]')
    .replace(/\b(token|secret|password|authorization|cookie)\s*([:=])\s*([^\s,;]+)/gi, '$1$2[REDACTED]')
}

class TelegramTerminalLogger {
  constructor({ token, allowedUserIds, batchIntervalMs = 900 }) {
    this.token = String(token || '').trim()
    this.allowedPrincipals = parseAllowedPrincipals(allowedUserIds)
    this.batchIntervalMs = batchIntervalMs
    this.activeChatIds = new Set()
    this.pendingOutput = ''
    this.flushTimer = null
    this.isFlushing = false
    this.isSending = false
    this.bot = null
    this.originalStdoutWrite = null
    this.originalStderrWrite = null
  }

  get isConfigured() {
    return Boolean(this.token && this.allowedPrincipals.size)
  }

  isAuthorized(ctx) {
    const userId = normalizeAllowedPrincipal(ctx.from?.id)
    const username = normalizeAllowedPrincipal(ctx.from?.username)
    return this.allowedPrincipals.has(userId) || (username && this.allowedPrincipals.has(username))
  }

  async requireAuthorizedPrivateChat(ctx) {
    if (!this.isAuthorized(ctx)) {
      await ctx.reply('You are not authorized to control terminal logging.')
      return false
    }

    if (ctx.chat?.type !== 'private') {
      await ctx.reply('For safety, terminal logging can only be controlled in a private chat.')
      return false
    }

    return true
  }

  attachTerminalCapture() {
    if (this.originalStdoutWrite) return

    this.originalStdoutWrite = process.stdout.write
    this.originalStderrWrite = process.stderr.write

    const intercept = (originalWrite) => {
      return (...args) => {
        const result = originalWrite.apply(process.stdout, args)
        if (!this.isSending) this.capture(args[0])
        return result
      }
    }

    process.stdout.write = intercept(this.originalStdoutWrite)
    process.stderr.write = (...args) => {
      const result = this.originalStderrWrite.apply(process.stderr, args)
      if (!this.isSending) this.capture(args[0])
      return result
    }
  }

  capture(chunk) {
    if (!this.activeChatIds.size || chunk === undefined || chunk === null) return

    const output = normalizeTerminalOutput(chunk)
    if (!output) return

    const available = MAX_BUFFER_LENGTH - this.pendingOutput.length
    if (available <= 0) return

    this.pendingOutput += output.slice(0, available)
    if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => this.flush(), this.batchIntervalMs)
      this.flushTimer.unref?.()
    }
  }

  splitMessages(output) {
    const messages = []
    let remaining = output

    while (remaining.length > MAX_TELEGRAM_MESSAGE_LENGTH) {
      let boundary = remaining.lastIndexOf('\n', MAX_TELEGRAM_MESSAGE_LENGTH)
      if (boundary <= 0) boundary = MAX_TELEGRAM_MESSAGE_LENGTH
      messages.push(remaining.slice(0, boundary))
      remaining = remaining.slice(boundary)
    }

    if (remaining) messages.push(remaining)
    return messages
  }

  writeInternalError(error) {
    const message = `[Telegram terminal logger] ${error?.message || error}\n`
    this.originalStderrWrite?.call(process.stderr, message)
  }

  async flush() {
    this.flushTimer = null
    if (this.isFlushing || !this.pendingOutput || !this.activeChatIds.size) return

    this.isFlushing = true
    const output = this.pendingOutput
    this.pendingOutput = ''

    try {
      const messages = this.splitMessages(output)
      for (const chatId of [...this.activeChatIds]) {
        for (const message of messages) {
          this.isSending = true
          try {
            await this.bot.telegram.sendMessage(chatId, message)
          } catch (error) {
            // A blocked/deleted chat cannot receive future logs.
            if ([403, 400].includes(error?.response?.error_code)) {
              this.activeChatIds.delete(chatId)
            }
            this.writeInternalError(error)
            break
          } finally {
            this.isSending = false
          }
        }
      }
    } finally {
      this.isFlushing = false
      if (this.pendingOutput && this.activeChatIds.size && !this.flushTimer) {
        this.flushTimer = setTimeout(() => this.flush(), this.batchIntervalMs)
        this.flushTimer.unref?.()
      }
    }
  }

  async start() {
    if (!this.isConfigured) return false

    this.bot = new Telegraf(this.token)
    this.bot.command('startlog', async (ctx) => {
      if (!(await this.requireAuthorizedPrivateChat(ctx))) return
      this.activeChatIds.add(ctx.chat.id)
      await ctx.reply('Terminal logging is now active. Send /stoplog to stop it.')
    })
    this.bot.command('stoplog', async (ctx) => {
      if (!(await this.requireAuthorizedPrivateChat(ctx))) return
      this.activeChatIds.delete(ctx.chat.id)
      await ctx.reply('Terminal logging has stopped for this chat.')
    })
    this.bot.command('logstatus', async (ctx) => {
      if (!(await this.requireAuthorizedPrivateChat(ctx))) return
      await ctx.reply(
        this.activeChatIds.has(ctx.chat.id)
          ? 'Terminal logging is active for this chat.'
          : 'Terminal logging is stopped for this chat.',
      )
    })
    this.bot.catch((error) => this.writeInternalError(error))

    this.attachTerminalCapture()
    // The application owns process lifecycle handling. Do not install Telegraf signal
    // handlers, because they would otherwise replace Node's normal Ctrl+C/SIGTERM exit.
    await this.bot.launch({ dropPendingUpdates: true, handleSignals: false })
    return true
  }

  stop(reason = 'shutdown') {
    if (this.flushTimer) clearTimeout(this.flushTimer)
    this.flushTimer = null
    this.activeChatIds.clear()
    this.bot?.stop(reason)
  }
}

async function startTelegramTerminalLogger(options) {
  const logger = new TelegramTerminalLogger(options)
  if (!logger.isConfigured) return null
  await logger.start()
  return logger
}

module.exports = { startTelegramTerminalLogger }
