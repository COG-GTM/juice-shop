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
  return res.statusCode >= 400 && res.statusCode < 600 ? res.statusCode : 500
}

function escapeHtml (text: string) {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}

function renderBody (req: Request, status: number, statusText: string, message: string) {
  switch (req.accepts(['html', 'json', 'text'])) {
    case 'json':
      return { type: 'application/json; charset=utf-8', body: JSON.stringify({ error: { status, message } }) }
    case 'text':
      return { type: 'text/plain; charset=utf-8', body: message }
    default:
      return { type: 'text/html; charset=utf-8', body: `<!DOCTYPE html><html><head><title>${escapeHtml(statusText)}</title></head><body><h1>${status} ${escapeHtml(statusText)}</h1><p>${escapeHtml(message)}</p></body></html>` }
  }
}

// Client errors keep their message; server errors only expose the status text. Stack traces are never sent.
export function genericErrorHandler () {
  return (err: any, req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) {
      next(err)
      return
    }
    const status = resolveStatus(err, res)
    const statusText = STATUS_CODES[status] ?? 'Error'
    const message = status < 500 && typeof err?.message === 'string' && err.message !== '' ? `Error: ${err.message}` : statusText
    const details = err instanceof Error ? (err.stack ?? err.message) : String(err)
    if (status >= 500) {
      logger.error(`${req.method} ${req.originalUrl} failed with ${status}: ${details}`)
    }
    const { type, body } = renderBody(req, status, statusText, message)
    res.statusCode = status
    res.setHeader('Content-Security-Policy', "default-src 'none'")
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Content-Type', type)
    res.setHeader('Content-Length', Buffer.byteLength(body))
    res.end(body)
  }
}
