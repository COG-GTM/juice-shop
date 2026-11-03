/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'

const PREFIX = 'enc:v1:'
const ALGORITHM = 'aes-256-gcm'
const IV_LENGTH = 12

export function parseKey (raw: string | undefined): Buffer {
  if (raw === undefined || raw === '') {
    // The SQLite database is recreated on every start, so an ephemeral key never strands stored secrets
    return crypto.randomBytes(32)
  }
  const key = /^[0-9a-fA-F]{64}$/.test(raw) ? Buffer.from(raw, 'hex') : Buffer.from(raw, 'base64')
  if (key.length !== 32) {
    throw new Error('JUICE_SHOP_TOTP_ENCRYPTION_KEY must be 32 bytes encoded as hex (64 chars) or base64')
  }
  return key
}

const key = parseKey(process.env.JUICE_SHOP_TOTP_ENCRYPTION_KEY)

export function isSealed (stored: string | null | undefined): boolean {
  return typeof stored === 'string' && stored.startsWith(PREFIX)
}

export function seal (secret: string, encryptionKey: Buffer = key): string {
  if (secret === '') return ''
  const iv = crypto.randomBytes(IV_LENGTH)
  const cipher = crypto.createCipheriv(ALGORITHM, encryptionKey, iv)
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()])
  return PREFIX + [iv, cipher.getAuthTag(), ciphertext].map(part => part.toString('base64url')).join('.')
}

export function open (stored: string | null | undefined, encryptionKey: Buffer = key): string {
  if (stored == null || stored === '') return ''
  if (!isSealed(stored)) return stored
  const [iv, tag, ciphertext] = stored.slice(PREFIX.length).split('.').map(part => Buffer.from(part, 'base64url'))
  const decipher = crypto.createDecipheriv(ALGORITHM, encryptionKey, iv)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8')
}
