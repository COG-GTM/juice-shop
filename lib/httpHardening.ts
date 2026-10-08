/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { STATUS_CODES } from 'node:http'
import config from 'config'
import { type CorsOptions } from 'cors'
import { type NextFunction, type Request, type Response } from 'express'
import logger from './logger'

const VERBOSE_ERROR_ENVIRONMENTS = ['development', 'test']

export function loadCookieParserSecret (env: NodeJS.ProcessEnv = process.env): string {
  const secret = env.COOKIE_PARSER_SECRET?.trim()
  return secret !== undefined && secret !== '' ? secret : crypto.randomBytes(32).toString('hex')
}

export function corsAllowedOrigins (env: NodeJS.ProcessEnv = process.env): string[] {
  const origins = env.CORS_ALLOWED_ORIGINS ?? `${config.get<string>('server.baseUrl')},http://localhost:4200`
  return origins.split(',').map(origin => origin.trim().replace(/\/+$/, '')).filter(origin => origin !== '')
}

export function corsOptions (allowedOrigins: string[] = corsAllowedOrigins()): CorsOptions {
  return {
    origin: (origin, callback) => {
      callback(null, origin !== undefined && allowedOrigins.includes(origin))
    }
  }
}

export function exposeErrorDetails (env: NodeJS.ProcessEnv = process.env): boolean {
  return VERBOSE_ERROR_ENVIRONMENTS.includes(env.NODE_ENV ?? '')
}

export const genericErrorHandler = () => (err: any, req: Request, res: Response, next: NextFunction) => {
  if (res.headersSent) {
    next(err)
    return
  }
  const errorStatus = Number(err?.status ?? err?.statusCode ?? res.statusCode)
  const status = errorStatus >= 400 && errorStatus < 600 ? errorStatus : 500
  if (status >= 500) {
    logger.error(`${req.method} ${req.path} failed: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`)
  }
  res.status(status).type('text/plain').send(STATUS_CODES[status] ?? 'Error')
}
