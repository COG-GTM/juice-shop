/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'

export const RESET_TOKEN_TTL_MS = 15 * 60 * 1000
export const MAX_FAILED_RESET_ATTEMPTS = 5
export const RESET_LOCKOUT_MS = 15 * 60 * 1000

export type PasswordResetMailer = (email: string, token: string) => Promise<void>

interface ResetTokenEntry {
  userId: number
  expiresAt: number
}

interface FailedAttemptsEntry {
  count: number
  windowStart: number
  lockedUntil: number
}

const resetTokens = new Map<string, ResetTokenEntry>()
const failedAttempts = new Map<string, FailedAttemptsEntry>()

const hashToken = (token: string) => crypto.createHash('sha256').update(token).digest('hex')
const accountKey = (email: string) => email.trim().toLowerCase()

// Default delivery drops the reset email into a server-side outbox that is not exposed over HTTP.
// Deployments should plug in a real mail transport via setPasswordResetMailer().
const outboxMailer: PasswordResetMailer = async (email, token) => {
  const outbox = path.resolve('mail/outbox')
  await fs.mkdir(outbox, { recursive: true })
  const message = [
    `To: ${email}`,
    'Subject: Password reset',
    '',
    'Use the following single-use code to reset your password. It expires in 15 minutes.',
    '',
    token,
    ''
  ].join('\r\n')
  await fs.writeFile(path.join(outbox, `${Date.now()}-${crypto.randomUUID()}.eml`), message, { mode: 0o600 })
}

let mailer: PasswordResetMailer = outboxMailer

export const setPasswordResetMailer = (newMailer?: PasswordResetMailer) => {
  mailer = newMailer ?? outboxMailer
}

export const invalidateResetTokens = (userId: number) => {
  for (const [hash, entry] of resetTokens) {
    if (entry.userId === userId) {
      resetTokens.delete(hash)
    }
  }
}

export const issueResetToken = async (userId: number, email: string) => {
  invalidateResetTokens(userId)
  const token = crypto.randomBytes(32).toString('hex')
  resetTokens.set(hashToken(token), { userId, expiresAt: Date.now() + RESET_TOKEN_TTL_MS })
  await mailer(email, token)
}

export const isValidResetToken = (token: string, userId: number) => {
  const entry = resetTokens.get(hashToken(token))
  if (!entry) {
    return false
  }
  if (entry.expiresAt <= Date.now()) {
    resetTokens.delete(hashToken(token))
    return false
  }
  return entry.userId === userId
}

export const isLockedOut = (email: string) => {
  const entry = failedAttempts.get(accountKey(email))
  return entry !== undefined && entry.lockedUntil > Date.now()
}

export const registerFailedAttempt = (email: string) => {
  const key = accountKey(email)
  const now = Date.now()
  let entry = failedAttempts.get(key)
  if (!entry || (entry.lockedUntil <= now && now - entry.windowStart > RESET_LOCKOUT_MS)) {
    entry = { count: 0, windowStart: now, lockedUntil: 0 }
  }
  entry.count++
  if (entry.count >= MAX_FAILED_RESET_ATTEMPTS) {
    entry.lockedUntil = now + RESET_LOCKOUT_MS
    entry.count = 0
    entry.windowStart = now
  }
  failedAttempts.set(key, entry)
}

export const clearFailedAttempts = (email: string) => {
  failedAttempts.delete(accountKey(email))
}

export const resetPasswordResetState = () => {
  resetTokens.clear()
  failedAttempts.clear()
}
