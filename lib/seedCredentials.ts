/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import config from 'config'
import type { StaticUser } from '../data/staticData'

const privilegedRoles = ['admin', 'accounting']
const publishedCustomerCredentialKeys = ['rapper', 'amy']
const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export function staticSeedCredentialsEnabled (): boolean {
  return config.has('application.staticSeedCredentials') && config.get<boolean>('application.staticSeedCredentials')
}

export function hasPublishedCredentials (user: Pick<StaticUser, 'key' | 'role'>): boolean {
  return privilegedRoles.includes(user.role) || publishedCustomerCredentialKeys.includes(user.key)
}

function randomSecret (): string {
  return crypto.randomBytes(24).toString('base64url')
}

function randomTotpSecret (): string {
  return Array.from(crypto.randomBytes(32), byte => base32Alphabet[byte & 31]).join('')
}

export function adminPasswordOverride (publishedPassword: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const password = env.JUICE_SHOP_ADMIN_PASSWORD
  if (password === undefined || password.length < 12 || password === publishedPassword) return undefined
  return password
}

export function withGeneratedCredentials (user: StaticUser, env: NodeJS.ProcessEnv = process.env): StaticUser {
  return {
    ...user,
    password: (user.key === 'admin' ? adminPasswordOverride(user.password, env) : undefined) ?? randomSecret(),
    totpSecret: user.totpSecret ? randomTotpSecret() : user.totpSecret,
    securityQuestion: user.securityQuestion != null ? { ...user.securityQuestion, answer: randomSecret() } : undefined
  }
}

export function secureSeedUsers (users: StaticUser[], keepStaticCredentials = staticSeedCredentialsEnabled(), env: NodeJS.ProcessEnv = process.env): StaticUser[] {
  if (keepStaticCredentials) return users
  return users.map(user => hasPublishedCredentials(user) ? withGeneratedCredentials(user, env) : user)
}
