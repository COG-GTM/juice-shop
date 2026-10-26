/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request } from 'express'
import { rateLimit } from 'express-rate-limit'
import * as security from './insecurity'

export const maxFailedAttemptsPerAccount = 5

/* Keyed on the socket address because req.ip follows the client-controlled X-Forwarded-For header while 'trust proxy' is enabled */
export const clientKey = (req: Request) => req.socket?.remoteAddress ?? 'unknown'

export const accountKey = (req: Request) => {
  const userId = security.verifySecondFactorToken(req.body?.tmpToken)?.userId
  return userId !== undefined && userId !== null && userId !== '' ? `2fa-user:${userId}` : undefined
}

export const perClient = () => rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 100,
  keyGenerator: clientKey,
  validate: { trustProxy: false }
})

/* Locks second-factor verification for an account after a few failed codes, regardless of client address */
export const perAccount = () => rateLimit({
  windowMs: 15 * 60 * 1000,
  max: maxFailedAttemptsPerAccount,
  skipSuccessfulRequests: true,
  skip: (req: Request) => accountKey(req) === undefined,
  keyGenerator: (req: Request) => accountKey(req) as string,
  validate: { trustProxy: false }
})
