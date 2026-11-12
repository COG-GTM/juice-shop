/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type NextFunction, type Request, type Response } from 'express'
import { rateLimit } from 'express-rate-limit'

import * as security from './insecurity'

/* Number of reverse proxies in front of the server. Without any, req.ip is the socket address and cannot be spoofed via X-Forwarded-For */
export function trustedProxyHops (value = process.env.JUICE_SHOP_TRUSTED_PROXY_HOPS): number | false {
  const hops = Number(value)
  return value !== undefined && value.trim() !== '' && Number.isInteger(hops) && hops > 0 ? hops : false
}

function defaultRequestWasSuccessful (req: Request, res: Response) {
  return res.statusCode < 400
}

/* Caps failed attempts against a single account no matter how many client addresses they come from */
export function accountRateLimit (accountOf: (req: Request) => string | undefined, { windowMs = 15 * 60 * 1000, max = 10, requestWasSuccessful = defaultRequestWasSuccessful } = {}) {
  return rateLimit({
    windowMs,
    max,
    skipSuccessfulRequests: true,
    requestWasSuccessful,
    keyGenerator: (req: Request) => `account:${accountOf(req) ?? '<none>'}`
  })
}

/* Keyed by the exact email the reset and login routes look up, so case variants of an address are separate accounts. Non-string emails (arrays, objects) all share one bucket so they cannot be varied to dodge the limit */
export function emailOf (req: Request) {
  const email = req.body?.email
  if (typeof email === 'string') return email.trim() !== '' ? email : undefined
  return email ? '<non-string>' : undefined
}

export function secondFactorUserOf (req: Request) {
  try {
    const userId = security.verifySecondFactorToken(req.body?.tmpToken).userId
    return typeof userId === 'number' || (typeof userId === 'string' && userId !== '') ? String(userId) : undefined
  } catch {
    return undefined
  }
}

/* A correct password for a 2FA account is answered with 401 'totp_token_required' and must not count as a failed login */
function flagSecondFactorRequired (req: Request, res: Response, next: NextFunction) {
  const json = res.json.bind(res)
  res.json = ((body?: any) => {
    if (body?.status === 'totp_token_required') res.locals.passwordAccepted = true
    return json(body)
  }) as Response['json']
  next()
}

export function passwordAccepted (req: Request, res: Response) {
  return res.statusCode < 400 || res.locals.passwordAccepted === true
}

/* Failed logins are capped per client address and per account, so neither rotating X-Forwarded-For nor spraying from many hosts allows unlimited guessing */
export function loginRateLimit ({ windowMs = 15 * 60 * 1000, maxPerClient = 100, maxPerAccount = 10 } = {}) {
  return [
    flagSecondFactorRequired,
    rateLimit({
      windowMs,
      max: maxPerClient,
      skipSuccessfulRequests: true,
      requestWasSuccessful: passwordAccepted
    }),
    accountRateLimit(emailOf, { windowMs, max: maxPerAccount, requestWasSuccessful: passwordAccepted })
  ]
}
