/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import logger from './logger'

export type ContinueCodeScope = 'hacking' | 'findIt' | 'fixIt'

const SIGNATURE_LENGTH = 64
const MIN_SECRET_LENGTH = 32

// Set CONTINUE_CODE_SECRET (min. 32 chars) to keep continue codes valid across server restarts
const resolveSecret = (configured: string | undefined) => {
  if (configured !== undefined && configured.length >= MIN_SECRET_LENGTH) return configured
  if (configured !== undefined && configured !== '') {
    logger.warn(`CONTINUE_CODE_SECRET is shorter than ${MIN_SECRET_LENGTH} characters and will be ignored; using a random per-process secret instead`)
  }
  return crypto.randomBytes(32).toString('hex')
}

const secret = resolveSecret(process.env.CONTINUE_CODE_SECRET)

const signatureOf = (code: string, scope: ContinueCodeScope) =>
  crypto.createHmac('sha256', secret).update(`${scope}:${code}`).digest('hex')

export const sign = (code: string, scope: ContinueCodeScope) => code + signatureOf(code, scope)

export const verify = (signedCode: string, scope: ContinueCodeScope): string | null => {
  if (signedCode.length <= SIGNATURE_LENGTH) return null
  const code = signedCode.slice(0, -SIGNATURE_LENGTH)
  const actual = Buffer.from(signedCode.slice(-SIGNATURE_LENGTH))
  const expected = Buffer.from(signatureOf(code, scope))
  return crypto.timingSafeEqual(actual, expected) ? code : null
}
