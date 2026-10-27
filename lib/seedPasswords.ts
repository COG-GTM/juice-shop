/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import config from 'config'

import { roles } from './insecurity'

const protectedCustomerAccounts = ['rapper', 'amy']

export const seedPasswordEnvVar = (key: string) => `JUICE_SHOP_SEED_PASSWORD_${key.replace(/[^a-z0-9]/gi, '_').toUpperCase()}`

export const isProtectedSeedAccount = (key: string, role?: string) => role === roles.admin || protectedCustomerAccounts.includes(key)

export function resolveSeedPassword ({ key, role, password }: { key: string, role?: string, password?: string }, useStaticSeedPasswords = config.get<boolean>('application.useStaticSeedPasswords')) {
  const configuredPassword = process.env[seedPasswordEnvVar(key)]
  if (configuredPassword) return { password: configuredPassword, randomized: false }
  if (useStaticSeedPasswords || !isProtectedSeedAccount(key, role)) return { password, randomized: false }
  return { password: crypto.randomBytes(24).toString('base64url'), randomized: true }
}
