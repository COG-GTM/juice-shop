/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request } from 'express'
import { rateLimit } from 'express-rate-limit'
import * as security from './insecurity'

export const maxFailedAttemptsPerAccount = 5
export const accountLockoutWindowMs = 15 * 60 * 1000
export const maxAttemptsPerClient = 100
export const clientWindowMs = 5 * 60 * 1000

export const trustedProxyHops = (value = process.env.JUICE_SHOP_TRUSTED_PROXY_HOPS) => {
  const hops = Number(value ?? 0)
  return Number.isInteger(hops) && hops >= 0 ? hops : 0
}

/* The global 'trust proxy' setting makes req.ip follow any client-supplied X-Forwarded-For value,
   so only as many X-Forwarded-For entries as there are trusted proxy hops in front of the app are honoured here */
export const clientAddress = (req: Request, hops = trustedProxyHops()) => {
  const socketAddress = req.socket?.remoteAddress ?? 'unknown'
  if (hops === 0) return socketAddress
  const header = req.headers?.['x-forwarded-for']
  const forwarded = (Array.isArray(header) ? header.join(',') : header ?? '')
    .split(',')
    .map((address) => address.trim())
    .filter((address) => address !== '')
  const chain = [socketAddress, ...forwarded.reverse()]
  return chain[Math.min(hops, chain.length - 1)]
}

export const accountKey = (req: Request) => {
  const userId = security.verifySecondFactorToken(req.body?.tmpToken)?.userId
  return userId === undefined ? undefined : `2fa-user:${userId}`
}

const validate = { trustProxy: false, xForwardedForHeader: false }

export const perClient = () => rateLimit({
  windowMs: clientWindowMs,
  limit: maxAttemptsPerClient,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => clientAddress(req),
  validate
})

/* Locks the second factor of an account after a few wrong codes, no matter which client address they come from */
export const perAccount = () => rateLimit({
  windowMs: accountLockoutWindowMs,
  limit: maxFailedAttemptsPerAccount,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  skip: (req: Request) => accountKey(req) === undefined,
  keyGenerator: (req: Request) => accountKey(req) as string,
  validate
})
