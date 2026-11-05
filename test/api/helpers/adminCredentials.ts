/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

function requireEnv (name: string): string {
  const value = process.env[name]
  if (!value) throw new Error(`${name} must be set for API tests (see test/api/helpers/test-env.mjs)`)
  return value
}

export const ADMIN_PASSWORD = requireEnv('JUICE_SHOP_ADMIN_PASSWORD')
export const SUPPORT_PASSWORD = requireEnv('JUICE_SHOP_SUPPORT_PASSWORD')
export const JANNIK_PASSWORD = requireEnv('JUICE_SHOP_JANNIK_PASSWORD')
export const TIMO_PASSWORD = requireEnv('JUICE_SHOP_TIMO_PASSWORD')
export const TIMO_TOTP_SECRET = requireEnv('JUICE_SHOP_TIMO_TOTP_SECRET')
export const BJOERN_PASSWORD = requireEnv('JUICE_SHOP_BJOERN_PASSWORD')
export const BJOERN_GOOGLE_PASSWORD = requireEnv('JUICE_SHOP_BJOERNGOOGLE_PASSWORD')
