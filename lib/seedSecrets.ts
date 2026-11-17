/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { generateSecret } from 'otplib'

const fromEnv = (name: string) => {
  const value = process.env[name]
  return value !== undefined && value !== '' ? value : undefined
}

const randomSecret = () => crypto.randomBytes(32).toString('hex')

export const cookieSecret = fromEnv('JUICE_SHOP_COOKIE_SECRET') ?? randomSecret()
export const hmacKey = fromEnv('JUICE_SHOP_HMAC_KEY') ?? randomSecret()

export const adminPasswordGenerated = fromEnv('JUICE_SHOP_ADMIN_PASSWORD') === undefined
export const adminPassword = fromEnv('JUICE_SHOP_ADMIN_PASSWORD') ?? crypto.randomBytes(24).toString('base64url')
export const totpSecret = fromEnv('JUICE_SHOP_TOTP_SECRET') ?? generateSecret()

let mnemonic: Promise<string> | undefined
export async function nftMnemonic (): Promise<string> {
  mnemonic ??= (async () => {
    const configured = fromEnv('JUICE_SHOP_NFT_MNEMONIC')
    if (configured !== undefined) return configured
    const { Mnemonic } = await import('ethers')
    return Mnemonic.fromEntropy(crypto.randomBytes(16)).phrase
  })()
  return await mnemonic
}

export const seededCredentials: Record<string, { password?: string, totpSecret?: string }> = {
  admin: { password: adminPassword },
  timo: { totpSecret }
}
