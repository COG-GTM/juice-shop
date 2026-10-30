/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request } from 'express'
import { rateLimit } from 'express-rate-limit'

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
    keyGenerator: (req: Request) => `account:${accountOf(req) ?? '<none>'}`,
    validate: false
  })
}

/* Keyed by the exact email the reset route looks up, so case variants of an address are separate accounts. Non-string emails (arrays, objects) all share one bucket so they cannot be varied to dodge the limit */
export function emailOf (req: Request) {
  const email = req.body?.email
  if (typeof email === 'string') return email.trim() !== '' ? email : undefined
  return email ? '<non-string>' : undefined
}
