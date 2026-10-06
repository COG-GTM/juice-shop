/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request } from 'express'
import { rateLimit } from 'express-rate-limit'

const windowMs = 5 * 60 * 1000

/* Number of reverse proxies in front of the app; without any, req.ip is the socket address and not header-derived */
export function trustedProxyHops (value = process.env.JUICE_SHOP_TRUSTED_PROXY_HOPS): number | false {
  const hops = Number(value)
  return Number.isInteger(hops) && hops > 0 ? hops : false
}

export function clientRateLimit (max = 100) {
  return rateLimit({ windowMs, max })
}

/* Caps attempts against a single targeted account regardless of how many client addresses they come from */
export function accountRateLimit (accountOf: (req: Request) => string | undefined, max = 10) {
  return rateLimit({
    windowMs,
    max,
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
