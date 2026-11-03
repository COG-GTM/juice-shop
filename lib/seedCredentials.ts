import crypto from 'node:crypto'
import { generateSecret } from 'otplib'
import * as security from './insecurity'
import type { StaticUser } from '../data/staticData'

export const privilegedRoles: string[] = [security.roles.admin, security.roles.accounting, security.roles.deluxe]

export function seedEnvSuffix (key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase()
}

export function resolveSeedCredentials (
  user: Pick<StaticUser, 'key' | 'role' | 'password' | 'totpSecret'>,
  useDefaultCredentials: boolean,
  env: NodeJS.ProcessEnv = process.env
): { password: string, totpSecret?: string, randomized: boolean } {
  if (!privilegedRoles.includes(user.role)) {
    return { password: user.password, totpSecret: user.totpSecret, randomized: false }
  }

  const suffix = seedEnvSuffix(user.key)
  const envPassword = env[`JUICE_SHOP_SEED_PASSWORD_${suffix}`]
  const password = envPassword != null && envPassword !== ''
    ? envPassword
    : useDefaultCredentials
      ? user.password
      : crypto.randomBytes(24).toString('base64url')
  let randomized = !useDefaultCredentials && (envPassword == null || envPassword === '')

  let totpSecret: string | undefined
  if (user.totpSecret != null) {
    const envTotpSecret = env[`JUICE_SHOP_SEED_TOTP_SECRET_${suffix}`]
    totpSecret = envTotpSecret != null && envTotpSecret !== ''
      ? envTotpSecret
      : useDefaultCredentials
        ? user.totpSecret
        : generateSecret()
    if (!useDefaultCredentials && (envTotpSecret == null || envTotpSecret === '')) {
      randomized = true
    }
  }

  return { password, totpSecret, randomized }
}
