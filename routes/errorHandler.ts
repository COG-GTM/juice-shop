/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { STATUS_CODES } from 'node:http'
import { type Request, type Response, type NextFunction } from 'express'

import logger from '../lib/logger'

function resolveStatus (err: any, res: Response) {
  const status = Number(err?.status ?? err?.statusCode)
  if (Number.isInteger(status) && status >= 400 && status < 600) return status
  return res.statusCode >= 400 ? res.statusCode : 500
}

export function genericErrorHandler () {
  return (err: any, req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) {
      next(err)
      return
    }
    const status = resolveStatus(err, res)
    const message = STATUS_CODES[status] ?? 'Error'
    logger.error(`${req.method} ${req.originalUrl} failed with ${status}: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`)
    res.status(status)
    res.format({
      json: () => res.json({ error: { status, message } }),
      html: () => res.send(`<!DOCTYPE html><html><head><title>${message}</title></head><body><h1>${status} ${message}</h1></body></html>`),
      default: () => res.type('txt').send(message)
    })
  }
}
