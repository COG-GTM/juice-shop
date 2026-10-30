/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'

const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export const demoCredentialsEnabled = (): boolean => process.env.JUICE_SHOP_DEMO_CREDENTIALS === 'enabled'

const randomSecret = (): string => crypto.randomBytes(24).toString('base64url')

export function randomTotpSecret (): string {
  return Array.from(crypto.randomBytes(32), (byte) => base32Alphabet[byte % 32]).join('')
}

export function seedPasswordFor (password: string): string {
  return demoCredentialsEnabled() ? password : randomSecret()
}

export function seedTotpSecretFor (totpSecret: string | undefined): string | undefined {
  if (totpSecret == null || totpSecret === '' || demoCredentialsEnabled()) {
    return totpSecret
  }
  return randomTotpSecret()
}

export function seedSecurityAnswerFor (answer: string): string {
  return demoCredentialsEnabled() ? answer : randomSecret()
}
