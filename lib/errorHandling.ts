/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { STATUS_CODES } from 'node:http'
import { inspect } from 'node:util'
import { type NextFunction, type Request, type Response } from 'express'
import logger from './logger'

export function exposeErrorDetails (env: NodeJS.ProcessEnv = process.env): boolean {
  return env.NODE_ENV === 'development' || env.NODE_ENV === 'test'
}

export const genericErrorHandler = () => (err: any, req: Request, res: Response, next: NextFunction) => {
  if (res.headersSent) {
    next(err)
    return
  }
  const errorStatus = Number(err?.status ?? err?.statusCode ?? res.statusCode)
  const status = errorStatus >= 400 && errorStatus < 600 ? errorStatus : 500
  logger.error(`${req.method} ${req.path.replace(/[\r\n]/g, '')} failed with ${status}: ${inspect(err)}`)
  const message = STATUS_CODES[status] ?? 'Error'
  res.status(status)
  if (req.accepts(['html', 'json']) === 'json') {
    endWithText(res, 'application/json; charset=utf-8', JSON.stringify({ error: { status, message } }))
  } else {
    endWithText(res, 'text/plain; charset=utf-8', message)
  }
}

// res.send() would hand a Buffer to res.end(), which breaks middleware that rewrites string bodies (e.g. serveIndexMiddleware)
function endWithText (res: Response, contentType: string, body: string) {
  res.setHeader('Content-Type', contentType)
  res.setHeader('Content-Length', Buffer.byteLength(body))
  res.end(body)
}
