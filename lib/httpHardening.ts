/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { STATUS_CODES } from 'node:http'
import type { CorsOptions } from 'cors'
import type { NextFunction, Request, Response } from 'express'

const toOrigin = (value: string) => {
  try {
    return new URL(value.trim()).origin
  } catch {
    return undefined
  }
}

export const allowedCorsOrigins = (baseUrl: string, configured: string | undefined = process.env.CORS_ALLOWED_ORIGINS) => {
  const candidates = configured ?? `${baseUrl},http://localhost:4200`
  return candidates.split(',')
    .map(toOrigin)
    .filter((origin): origin is string => origin !== undefined && origin !== 'null')
}

export const corsOptions = (allowedOrigins: string[]): CorsOptions => ({
  origin: (origin, callback) => {
    callback(null, origin !== undefined && allowedOrigins.includes(origin))
  }
})

export const cookieSecret = (configured: string | undefined = process.env.COOKIE_PARSER_SECRET) => {
  return configured !== undefined && configured !== '' ? configured : crypto.randomBytes(32).toString('hex')
}

const escapeHtml = (text: string) => text.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`)

export const productionErrorHandler = (log: (message: string) => void = () => {}) => (err: any, req: Request, res: Response, next: NextFunction) => {
  if (res.headersSent) {
    next(err)
    return
  }
  const status = Number(err?.status ?? err?.statusCode)
  const statusCode = status >= 400 && status < 600 ? status : (res.statusCode >= 400 && res.statusCode < 600 ? res.statusCode : 500)
  const clientMessage = err instanceof Error ? `${err.name}: ${err.message}` : String(err)
  const message = statusCode < 500 ? clientMessage : (STATUS_CODES[statusCode] ?? 'Internal Server Error')
  log(`${req.method} ${req.path} failed with ${statusCode}: ${err instanceof Error ? err.stack : String(err)}`)
  const json = req.accepts(['html', 'json']) === 'json'
  res.statusCode = statusCode
  res.setHeader('Content-Type', json ? 'application/json; charset=utf-8' : 'text/html; charset=utf-8')
  res.end(json ? JSON.stringify({ error: { message } }) : escapeHtml(message))
}
