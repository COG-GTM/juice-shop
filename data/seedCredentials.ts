/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { generateSecret } from 'otplib'
import type { StaticUser, StaticUserSecurityQuestion } from './staticData'

export interface SeedCredentials {
  password: string
  totpSecret?: string
  securityQuestion?: StaticUserSecurityQuestion
  generatedAdminPassword?: string
}

export function demoCredentialsEnabled (env: NodeJS.ProcessEnv = process.env) {
  return env.JUICE_SHOP_DEMO_CREDENTIALS === 'true'
}

export function randomSecret () {
  return crypto.randomBytes(24).toString('base64url')
}

export function resolveSeedCredentials (user: Pick<StaticUser, 'key' | 'password' | 'totpSecret' | 'securityQuestion'>, env: NodeJS.ProcessEnv = process.env): SeedCredentials {
  if (demoCredentialsEnabled(env)) {
    return { password: user.password, totpSecret: user.totpSecret, securityQuestion: user.securityQuestion }
  }

  let password = randomSecret()
  let generatedAdminPassword: string | undefined
  if (user.key === 'admin') {
    if (env.JUICE_SHOP_ADMIN_PASSWORD) {
      password = env.JUICE_SHOP_ADMIN_PASSWORD
    } else {
      generatedAdminPassword = password
    }
  }

  return {
    password,
    totpSecret: user.totpSecret ? generateSecret() : user.totpSecret,
    securityQuestion: user.securityQuestion != null ? { id: user.securityQuestion.id, answer: randomSecret() } : undefined,
    generatedAdminPassword
  }
}
