/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'

export type ContinueCodeScope = 'hacking' | 'findIt' | 'fixIt'

const SIGNATURE_LENGTH = 64

// Set CONTINUE_CODE_SECRET to keep continue codes valid across server restarts
const secret = process.env.CONTINUE_CODE_SECRET !== undefined && process.env.CONTINUE_CODE_SECRET !== ''
  ? process.env.CONTINUE_CODE_SECRET
  : crypto.randomBytes(32).toString('hex')

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
