/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import config from 'config'
import { generateSecret } from 'otplib'
import type { StaticUser } from '../data/staticData'

export function staticAdminCredentialsEnabled (): boolean {
  const override = process.env.JUICE_SHOP_STATIC_ADMIN_CREDENTIALS
  if (override !== undefined && override !== '') {
    return override.toLowerCase() === 'true'
  }
  return config.has('application.staticAdminCredentials') && config.get<boolean>('application.staticAdminCredentials')
}

function randomSecret (): string {
  return crypto.randomBytes(24).toString('base64url')
}

export function withGeneratedCredentials (user: StaticUser): StaticUser {
  return {
    ...user,
    password: randomSecret(),
    totpSecret: user.totpSecret ? generateSecret() : user.totpSecret,
    securityQuestion: user.securityQuestion != null ? { ...user.securityQuestion, answer: randomSecret() } : undefined
  }
}
