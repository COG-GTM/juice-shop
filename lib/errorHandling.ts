/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { STATUS_CODES } from 'node:http'
import { type NextFunction, type Request, type Response } from 'express'
import logger from './logger'

const DETAILED_ERROR_ENVIRONMENTS = ['development', 'test']

export function exposeErrorDetails (env: NodeJS.ProcessEnv = process.env): boolean {
  return env.EXPOSE_ERROR_DETAILS === 'true' || DETAILED_ERROR_ENVIRONMENTS.includes(env.NODE_ENV ?? '')
}

export function parseJsonBody (body: string) {
  try {
    return JSON.parse(body)
  } catch (error) {
    throw Object.assign(new Error('Malformed JSON request body'), { status: 400, cause: error })
  }
}

export const genericErrorHandler = () => (err: any, req: Request, res: Response, next: NextFunction) => {
  if (res.headersSent) {
    next(err)
    return
  }
  const errorStatus = Number(err?.status ?? err?.statusCode ?? res.statusCode)
  const status = errorStatus >= 400 && errorStatus < 600 ? errorStatus : 500
  if (status >= 500) {
    logger.error(`${req.method} ${req.path.replace(/[\r\n]/g, '')} failed: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`)
  }
  res.status(status).type('text/plain').send(STATUS_CODES[status] ?? 'Error')
}
