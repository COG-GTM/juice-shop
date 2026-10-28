/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import type { StaticUser } from './staticData'

const privilegedRoles: Array<StaticUser['role']> = ['admin', 'accounting']

export const demoCredentialsEnabled = (): boolean => process.env.JUICE_SHOP_DEMO_CREDENTIALS === 'enabled'

export const isPrivilegedRole = (role: StaticUser['role']): boolean => privilegedRoles.includes(role)

export function seedPasswordFor ({ role, password }: Pick<StaticUser, 'role' | 'password'>): { password: string, generated: boolean } {
  if (!isPrivilegedRole(role) || demoCredentialsEnabled()) {
    return { password, generated: false }
  }
  return { password: crypto.randomBytes(24).toString('base64url'), generated: true }
}
