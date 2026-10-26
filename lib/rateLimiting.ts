/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request } from 'express'
import { rateLimit } from 'express-rate-limit'

import * as security from './insecurity'

/* Number of reverse proxies in front of the server. Without any, req.ip is the socket address and cannot be spoofed via X-Forwarded-For */
export function trustedProxyHops (value = process.env.JUICE_SHOP_TRUSTED_PROXY_HOPS): number | false {
  const hops = Number(value)
  return value !== undefined && value.trim() !== '' && Number.isInteger(hops) && hops > 0 ? hops : false
}

/* Caps failed attempts against a single account no matter how many client addresses they come from */
export function accountRateLimit (accountOf: (req: Request) => string | undefined, { windowMs = 15 * 60 * 1000, max = 10 } = {}) {
  return rateLimit({
    windowMs,
    max,
    skipSuccessfulRequests: true,
    skip: (req: Request) => accountOf(req) === undefined,
    keyGenerator: (req: Request) => `account:${accountOf(req)}`,
    validate: false
  })
}

export function emailOf (req: Request) {
  const email = req.body?.email
  return typeof email === 'string' && email.trim() !== '' ? email.trim().toLowerCase() : undefined
}

export function secondFactorUserOf (req: Request) {
  const tmpToken = req.body?.tmpToken
  if (typeof tmpToken !== 'string') return undefined
  try {
    const payload = security.verify(tmpToken) && security.decode(tmpToken)
    if (payload?.type !== 'password_valid_needs_second_factor_token') return undefined
    const userId = payload.userId
    return typeof userId === 'number' || (typeof userId === 'string' && userId !== '') ? String(userId) : undefined
  } catch {
    return undefined
  }
}
