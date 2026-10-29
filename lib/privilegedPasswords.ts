/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import logger from './logger'
import { roles } from './insecurity'
import * as utils from './utils'

const privilegedRoles: string[] = [roles.admin, roles.accounting]

export const generatedCredentialsFile = path.resolve('data/privileged-credentials.txt')

export function privilegedPasswordEnvVar (key: string) {
  return `JUICE_SHOP_${key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase()}_PASSWORD`
}

export function resolveUserPasswords (users: Array<{ key: string, role: string, password?: string }>, credentialsFile = generatedCredentialsFile) {
  const passwords: Record<string, string | undefined> = {}
  const generated: string[] = []
  for (const { key, role, password } of users) {
    if (!privilegedRoles.includes(role)) {
      passwords[key] = password
      continue
    }
    const envVar = privilegedPasswordEnvVar(key)
    const configured = process.env[envVar]
    if (configured) {
      passwords[key] = configured
      continue
    }
    const randomPassword = crypto.randomBytes(18).toString('base64url')
    passwords[key] = randomPassword
    generated.push(`${envVar}=${randomPassword}`)
  }
  if (generated.length > 0) {
    try {
      fs.rmSync(credentialsFile, { force: true })
      fs.writeFileSync(credentialsFile, generated.join('\n') + '\n', { mode: 0o600, flag: 'wx' })
    } catch (err) {
      throw new Error(`Could not write generated passwords for ${generated.length} privileged users to ${credentialsFile} (${utils.getErrorMessage(err)}). Set ${generated.map(line => line.split('=')[0]).join(', ')} instead.`)
    }
    logger.warn(`Generated random passwords for ${generated.length} privileged users and wrote them to ${credentialsFile} (set the listed environment variables to choose your own)`)
  }
  return passwords
}
