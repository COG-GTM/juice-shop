/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'

export const TOKEN_TTL_MS = 15 * 60 * 1000

interface PendingReset {
  tokenHash: Buffer
  expiresAt: number
}

const pendingResets = new Map<number, PendingReset>()

const hashToken = (token: string) => crypto.createHash('sha256').update(token).digest()

export function issueResetToken (userId: number): string {
  const token = crypto.randomBytes(32).toString('hex')
  pendingResets.set(userId, { tokenHash: hashToken(token), expiresAt: Date.now() + TOKEN_TTL_MS })
  return token
}

export function isValidResetToken (userId: number, token: unknown): boolean {
  const pending = pendingResets.get(userId)
  if (!pending || typeof token !== 'string' || token.length === 0) {
    return false
  }
  if (Date.now() > pending.expiresAt) {
    pendingResets.delete(userId)
    return false
  }
  return crypto.timingSafeEqual(pending.tokenHash, hashToken(token))
}

export function revokeResetToken (userId: number) {
  pendingResets.delete(userId)
}
