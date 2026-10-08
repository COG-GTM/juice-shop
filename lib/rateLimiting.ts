/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request } from 'express'
import { rateLimit } from 'express-rate-limit'

import * as security from './insecurity'

const windowMs = 5 * 60 * 1000

/* Number of reverse proxies in front of the server. Without any, req.ip is the socket address and cannot be spoofed via X-Forwarded-For */
export function trustedProxyHops (value = process.env.JUICE_SHOP_TRUSTED_PROXY_HOPS): number | false {
  const hops = Number(value)
  return value !== undefined && value.trim() !== '' && Number.isInteger(hops) && hops > 0 ? hops : false
}

/* Caps failed attempts against a single account no matter how many client addresses they come from */
export function accountRateLimit (accountOf: (req: Request) => string | undefined, max = 10) {
  return rateLimit({
    windowMs,
    max,
    skipSuccessfulRequests: true,
    keyGenerator: (req: Request) => {
      let account: string | undefined
      try {
        account = accountOf(req)
      } catch {
        account = undefined
      }
      return account ? `account:${account}` : `ip:${req.ip}`
    }
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
    if (!security.verify(tmpToken)) return undefined
    const userId = security.decode(tmpToken)?.userId
    return userId !== undefined && userId !== null ? String(userId) : undefined
  } catch {
    return undefined
  }
}
