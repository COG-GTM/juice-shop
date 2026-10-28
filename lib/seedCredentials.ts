/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import config from 'config'
import { generateSecret } from 'otplib'
import type { StaticUser } from '../data/staticData'

const privilegedRoles = ['admin', 'accounting']

export function staticPrivilegedCredentialsEnabled (): boolean {
  return config.has('application.staticPrivilegedCredentials') && config.get<boolean>('application.staticPrivilegedCredentials')
}

export function isPrivileged (role: string): boolean {
  return privilegedRoles.includes(role)
}

function randomSecret (): string {
  return crypto.randomBytes(24).toString('base64url')
}

export function adminPasswordOverride (publishedPassword: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const password = env.JUICE_SHOP_ADMIN_PASSWORD
  if (password === undefined || password === '' || password === publishedPassword) return undefined
  return password
}

export function withGeneratedCredentials (user: StaticUser, env: NodeJS.ProcessEnv = process.env): StaticUser {
  return {
    ...user,
    password: (user.key === 'admin' ? adminPasswordOverride(user.password, env) : undefined) ?? randomSecret(),
    totpSecret: user.totpSecret ? generateSecret() : user.totpSecret,
    securityQuestion: user.securityQuestion != null ? { ...user.securityQuestion, answer: randomSecret() } : undefined
  }
}

export function securePrivilegedUsers (users: StaticUser[], keepStaticCredentials = staticPrivilegedCredentialsEnabled(), env: NodeJS.ProcessEnv = process.env): StaticUser[] {
  if (keepStaticCredentials) return users
  return users.map(user => isPrivileged(user.role) ? withGeneratedCredentials(user, env) : user)
}
