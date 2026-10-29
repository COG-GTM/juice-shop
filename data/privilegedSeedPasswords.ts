/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import type { StaticUser } from './staticData'

const privilegedRoles: Array<StaticUser['role']> = ['admin', 'accounting']

export const minimumOperatorPasswordLength = 12

export type SeedPasswordSource = 'static' | 'operator' | 'generated'

export const demoCredentialsEnabled = (): boolean => process.env.JUICE_SHOP_DEMO_CREDENTIALS === 'enabled'

export const isPrivilegedRole = (role: StaticUser['role']): boolean => privilegedRoles.includes(role)

export function operatorAdminPassword (): string | undefined {
  const password = process.env.JUICE_SHOP_ADMIN_PASSWORD
  return password !== undefined && password.length >= minimumOperatorPasswordLength ? password : undefined
}

export function seedPasswordFor ({ key, role, password }: Pick<StaticUser, 'key' | 'role' | 'password'>): { password: string, source: SeedPasswordSource } {
  if (!isPrivilegedRole(role) || demoCredentialsEnabled()) {
    return { password, source: 'static' }
  }
  const operatorPassword = key === 'admin' ? operatorAdminPassword() : undefined
  if (operatorPassword !== undefined) {
    return { password: operatorPassword, source: 'operator' }
  }
  return { password: crypto.randomBytes(24).toString('base64url'), source: 'generated' }
}
