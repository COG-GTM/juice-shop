/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import net from 'node:net'
import config from 'config'
import { type Request } from 'express'
import { rateLimit } from 'express-rate-limit'

// IPv6 clients usually control a whole /64, so the budget is shared across that prefix
export function rateLimitKey (address: string | undefined) {
  if (address === undefined) return 'unknown'
  const mappedIPv4 = address.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i)
  if (mappedIPv4 !== null) return mappedIPv4[1]
  if (!net.isIPv6(address)) return address
  const [head, tail = ''] = address.split('%')[0].split('::')
  const headGroups = head === '' ? [] : head.split(':')
  const tailGroups = address.includes('::') ? (tail === '' ? [] : tail.split(':')) : []
  const groups = [...headGroups, ...Array(8 - headGroups.length - tailGroups.length).fill('0'), ...tailGroups]
  return groups.slice(0, 4).map(group => parseInt(group, 16).toString(16)).join(':') + '::/64'
}

// Keyed on the socket address so X-Forwarded-For cannot be used to reset the budget while 'trust proxy' is enabled
export function clientSocketAddress (req: Request) {
  return rateLimitKey(req.socket.remoteAddress)
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
