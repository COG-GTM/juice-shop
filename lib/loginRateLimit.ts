/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction, type RequestHandler } from 'express'
import { rateLimit } from 'express-rate-limit'

export const LOGIN_WINDOW_MS = 15 * 60 * 1000
export const MAX_FAILED_LOGINS_PER_ACCOUNT = 10
export const MAX_FAILED_LOGINS_PER_CLIENT = 100

const tooManyAttempts = 'Too many failed login attempts. Please try again later.'

export function loginAccountKey (req: Request): string | undefined {
  const email = typeof req.body === 'object' && req.body !== null ? req.body.email : undefined
  if (typeof email !== 'string') return undefined
  const key = email.trim().toLowerCase()
  return key !== '' ? key : undefined
}

// The socket address is used instead of req.ip because 'trust proxy' is enabled app-wide,
// which would let clients pick their own key via X-Forwarded-For.
export function loginClientKey (req: Request): string {
  return req.socket.remoteAddress ?? 'unknown'
}

export function loginRateLimit (): RequestHandler[] {
  const perClient = rateLimit({
    windowMs: LOGIN_WINDOW_MS,
    limit: MAX_FAILED_LOGINS_PER_CLIENT,
    skipSuccessfulRequests: true,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: tooManyAttempts,
    validate: false,
    keyGenerator: loginClientKey
  })

  const perAccount = rateLimit({
    windowMs: LOGIN_WINDOW_MS,
    limit: MAX_FAILED_LOGINS_PER_ACCOUNT,
    skipSuccessfulRequests: true,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: tooManyAttempts,
    validate: false,
    skip: (req: Request) => loginAccountKey(req) === undefined,
    keyGenerator: (req: Request) => loginAccountKey(req) as string
  })

  const resetAccountOnSuccess = (req: Request, res: Response, next: NextFunction) => {
    const key = loginAccountKey(req)
    if (key !== undefined) {
      res.on('finish', () => {
        if (res.statusCode === 200) {
          void perAccount.resetKey(key)
        }
      })
    }
    next()
  }

  return [perClient, perAccount, resetAccountOnSuccess]
}
