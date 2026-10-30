/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import type { StaticUser } from './staticData'

const privilegedRoles: Array<StaticUser['role']> = ['admin', 'accounting']
const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export const demoCredentialsEnabled = (): boolean => process.env.JUICE_SHOP_DEMO_CREDENTIALS === 'enabled'

export const isPrivilegedRole = (role: StaticUser['role']): boolean => privilegedRoles.includes(role)

export function randomTotpSecret (): string {
  return Array.from(crypto.randomBytes(32), (byte) => base32Alphabet[byte % 32]).join('')
}

export function seedPasswordFor ({ role, password }: Pick<StaticUser, 'role' | 'password'>): { password: string, generated: boolean } {
  if (!isPrivilegedRole(role) || demoCredentialsEnabled()) {
    return { password, generated: false }
  }
  return { password: crypto.randomBytes(24).toString('base64url'), generated: true }
}

export function seedTotpSecretFor ({ role, totpSecret }: Pick<StaticUser, 'role' | 'totpSecret'>): string | undefined {
  if (totpSecret == null || totpSecret === '' || !isPrivilegedRole(role) || demoCredentialsEnabled()) {
    return totpSecret
  }
  return randomTotpSecret()
}

export function seedSecurityAnswerFor ({ role, answer }: { role: StaticUser['role'], answer: string }): string {
  if (!isPrivilegedRole(role) || demoCredentialsEnabled()) {
    return answer
  }
  return crypto.randomBytes(24).toString('base64url')
}
