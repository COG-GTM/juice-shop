/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request } from 'express'
import { rateLimit } from 'express-rate-limit'

// Keyed on the socket address so X-Forwarded-For cannot be used to reset the budget while 'trust proxy' is enabled
export function clientSocketAddress (req: Request) {
  return req.socket.remoteAddress ?? 'unknown'
}

export function globalRateLimit (
  windowMs: number = config.get<number>('server.rateLimit.windowMs'),
  limit: number = config.get<number>('server.rateLimit.max')
) {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    keyGenerator: clientSocketAddress,
    validate: { trustProxy: false, xForwardedForHeader: false }
  })
}
