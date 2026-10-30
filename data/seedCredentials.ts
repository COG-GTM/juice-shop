/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import config from 'config'
import { generateSecret } from 'otplib'

export interface SeedCredentials {
  password: string
  totpSecret?: string
  securityAnswer?: string
}

export function randomCredential (): string {
  return crypto.randomBytes(24).toString('base64url')
}

export function seedKnownCredentialsEnabled (): boolean {
  return config.has('application.seedKnownCredentials') && config.get<boolean>('application.seedKnownCredentials')
}

export function seededCredentials (key: string, known: SeedCredentials, seedKnownCredentials: boolean, adminPassword = process.env.JUICE_SHOP_ADMIN_PASSWORD): SeedCredentials {
  if (seedKnownCredentials) return known
  return {
    password: key === 'admin' && adminPassword ? adminPassword : randomCredential(),
    totpSecret: known.totpSecret ? generateSecret() : known.totpSecret,
    securityAnswer: known.securityAnswer != null ? randomCredential() : undefined
  }
}

export function seededSecurityAnswer (answer: string, seedKnownCredentials: boolean): string {
  return seedKnownCredentials ? answer : randomCredential()
}
