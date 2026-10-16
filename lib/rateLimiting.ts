/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { rateLimit } from 'express-rate-limit'

import * as security from './insecurity'

const windowMs = 5 * 60 * 1000

/* Value for Express' "trust proxy": a hop count or a list of proxy addresses/subnets. Unset means req.ip is the socket peer and X-Forwarded-For is ignored */
export function trustedProxies (value = process.env.JUICE_SHOP_TRUSTED_PROXIES): number | string[] | false {
  const setting = value?.trim() ?? ''
  if (setting === '' || setting === '0' || setting.toLowerCase() === 'false') return false
  if (/^\d+$/.test(setting)) return Number(setting)
  return setting.split(',').map(entry => entry.trim()).filter(Boolean)
}

/* Caps failed attempts per client IP and per targeted account, so rotating client addresses does not reset the budget */
export function failedAttemptLimits (accountOf: (req: Request) => string | undefined, { maxPerIp = 100, maxPerAccount = 10, requestWasSuccessful = (_req: Request, res: Response) => res.statusCode < 400 } = {}) {
  const common = { windowMs, skipSuccessfulRequests: true, requestWasSuccessful, validate: false }
  return [
    rateLimit({ ...common, max: maxPerIp, keyGenerator: (req: Request) => `ip:${req.ip}` }),
    rateLimit({
      ...common,
      max: maxPerAccount,
      skip: (req: Request) => accountOf(req) === undefined,
      keyGenerator: (req: Request) => `account:${accountOf(req)}`
    })
  ]
}

export function emailOf (req: Request) {
  const email = req.body?.email
  return typeof email === 'string' && email.trim() !== '' ? email.trim().toLowerCase() : undefined
}

export function secondFactorUserOf (req: Request) {
  const tmpToken = req.body?.tmpToken
  if (typeof tmpToken !== 'string') return undefined
  try {
    if (!security.verify(tmpToken)) return undefined
    const userId = security.decode(tmpToken)?.userId
    return userId !== undefined && userId !== null ? String(userId) : undefined
  } catch {
    return undefined
  }
}

/* A correct password for a 2FA-enabled account is answered with 401 "totp_token_required", which is not a failed login */
export function flagSecondFactorChallenge (_req: Request, res: Response, next: NextFunction) {
  const json = res.json.bind(res)
  res.json = (body?: any) => {
    if (body?.status === 'totp_token_required') res.locals.secondFactorRequired = true
    return json(body)
  }
  next()
}

export function loginWasSuccessful (_req: Request, res: Response) {
  return res.statusCode < 400 || res.locals.secondFactorRequired === true
}
