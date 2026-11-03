import crypto from 'node:crypto'
import { generateSecret } from 'otplib'
import * as security from './insecurity'
import type { StaticUser } from '../data/staticData'

export const privilegedRoles: string[] = [security.roles.admin, security.roles.accounting, security.roles.deluxe]

export function seedEnvSuffix (key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase()
}

export function resolveSeedCredentials (
  user: Pick<StaticUser, 'key' | 'role' | 'password' | 'totpSecret' | 'securityQuestion'>,
  useDefaultCredentials: boolean,
  env: NodeJS.ProcessEnv = process.env
): { password: string, totpSecret?: string, securityAnswer?: string, randomized: boolean, missingTotpOverride: boolean } {
  if (!privilegedRoles.includes(user.role)) {
    return {
      password: user.password,
      totpSecret: user.totpSecret,
      securityAnswer: user.securityQuestion?.answer,
      randomized: false,
      missingTotpOverride: false
    }
  }

  const suffix = seedEnvSuffix(user.key)
  const envPassword = env[`JUICE_SHOP_SEED_PASSWORD_${suffix}`]
  const hasPasswordOverride = envPassword != null && envPassword !== ''
  const password = envPassword != null && envPassword !== ''
    ? envPassword
    : useDefaultCredentials
      ? user.password
      : crypto.randomBytes(24).toString('base64url')
  let randomized = !useDefaultCredentials && !hasPasswordOverride

  let totpSecret: string | undefined
  let missingTotpOverride = false
  if (user.totpSecret != null) {
    const envTotpSecret = env[`JUICE_SHOP_SEED_TOTP_SECRET_${suffix}`]
    const hasTotpOverride = envTotpSecret != null && envTotpSecret !== ''
    totpSecret = envTotpSecret != null && envTotpSecret !== ''
      ? envTotpSecret
      : useDefaultCredentials
        ? user.totpSecret
        : generateSecret()
    if (!useDefaultCredentials && !hasTotpOverride) {
      randomized = true
      missingTotpOverride = hasPasswordOverride
    }
  }

  let securityAnswer: string | undefined
  if (user.securityQuestion != null) {
    const envSecurityAnswer = env[`JUICE_SHOP_SEED_SECURITY_ANSWER_${suffix}`]
    securityAnswer = envSecurityAnswer != null && envSecurityAnswer !== ''
      ? envSecurityAnswer
      : useDefaultCredentials
        ? user.securityQuestion.answer
        : crypto.randomBytes(24).toString('base64url')
    if (!useDefaultCredentials && (envSecurityAnswer == null || envSecurityAnswer === '')) {
      randomized = true
    }
  }

  return { password, totpSecret, securityAnswer, randomized, missingTotpOverride }
}
