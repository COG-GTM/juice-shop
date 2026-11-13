/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

function requestHost (req: Request) {
  const forwardedHost = req.app.enabled('trust proxy') ? req.get('x-forwarded-host')?.split(',')[0].trim() : undefined
  return forwardedHost ?? req.get('host')
}

export function isCrossSiteRequest (req: Request) {
  const source = req.get('origin') ?? req.get('referer')
  if (source === undefined) {
    return false
  }
  const host = requestHost(req)
  if (!host) {
    return true
  }
  try {
    const sourceUrl = new URL(source)
    const targetUrl = new URL(`${req.protocol}://${host}`)
    // An HTTPS origin is accepted for an HTTP request to support TLS-terminating proxies that omit X-Forwarded-Proto
    return sourceUrl.host !== targetUrl.host || (sourceUrl.protocol === 'http:' && targetUrl.protocol === 'https:')
  } catch {
    return true
  }
}

export function csrfProtection () {
  return function csrfProtectionMiddleware (req: Request, res: Response, next: NextFunction) {
    // Cross-origin requests without cookies (e.g. the Angular dev server on :4200) carry no ambient credentials to abuse
    if (SAFE_METHODS.has(req.method) || req.get('cookie') === undefined) {
      next()
      return
    }
    if (isCrossSiteRequest(req)) {
      res.status(403).json({ error: 'Cross-site request rejected' })
      return
    }
    next()
  }
}
