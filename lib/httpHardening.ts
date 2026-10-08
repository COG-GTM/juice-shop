/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import fs from 'node:fs'
import { STATUS_CODES } from 'node:http'
import path from 'node:path'
import config from 'config'
import { type CorsOptions } from 'cors'
import { type NextFunction, type Request, type Response } from 'express'
import logger from './logger'

const ANGULAR_DEV_SERVER_ORIGINS = ['http://localhost:4200', 'http://127.0.0.1:4200']

const isProduction = (env: NodeJS.ProcessEnv) => env.NODE_ENV === 'production'

export function corsAllowedOrigins (env: NodeJS.ProcessEnv = process.env): string[] {
  const origins = env.CORS_ALLOWED_ORIGINS?.split(',') ?? [config.get<string>('server.baseUrl'), ...(isProduction(env) ? [] : ANGULAR_DEV_SERVER_ORIGINS)]
  return origins.map(origin => origin.trim().replace(/\/+$/, '')).filter(origin => origin !== '' && origin !== 'null' && origin !== '*')
}

export function corsOptions (allowedOrigins: string[] = corsAllowedOrigins()): CorsOptions {
  return {
    origin: (origin, callback) => {
      callback(null, origin !== undefined && allowedOrigins.includes(origin))
    }
  }
}

export interface InlineScriptHashes {
  scripts: string[]
  handlers: string[]
}

const JAVASCRIPT_TYPES = ['', 'text/javascript', 'application/javascript', 'module']

const sha256Source = (text: string) => `'sha256-${crypto.createHash('sha256').update(text, 'utf8').digest('base64')}'`

const decodeAttribute = (value: string) => value
  .replace(/&quot;/g, '"')
  .replace(/&#39;|&apos;/g, '\'')
  .replace(/&lt;/g, '<')
  .replace(/&gt;/g, '>')
  .replace(/&amp;/g, '&')

const attribute = (attributes: string, name: string) => new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(attributes)

export function inlineScriptHashes (html: string): InlineScriptHashes {
  const scripts = new Set<string>()
  const handlers = new Set<string>()
  const markup = html.replace(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi, (_match, attributes: string, body: string) => {
    const type = attribute(attributes, 'type')
    const isJavaScript = JAVASCRIPT_TYPES.includes((type?.[1] ?? type?.[2] ?? type?.[3] ?? '').trim().toLowerCase())
    if (isJavaScript && attribute(attributes, 'src') === null) {
      scripts.add(sha256Source(body))
    }
    return `<script${attributes}></script>`
  })
  for (const [tag] of markup.matchAll(/<[a-z][^>]*>/gi)) {
    for (const [, doubleQuoted, singleQuoted] of tag.matchAll(/\son[a-z]+\s*=\s*(?:"([^"]*)"|'([^']*)')/gi)) {
      handlers.add(sha256Source(decodeAttribute(doubleQuoted ?? singleQuoted)))
    }
  }
  return { scripts: [...scripts], handlers: [...handlers] }
}

export function cspHeaderName (env: NodeJS.ProcessEnv = process.env): string {
  return isProduction(env) || env.CSP_ENFORCE === 'true' ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only'
}

export function contentSecurityPolicy ({ scripts, handlers }: InlineScriptHashes = { scripts: [], handlers: [] }): string {
  const directives: Record<string, string[]> = {
    'default-src': ["'self'"],
    'script-src': ["'self'", ...scripts, ...(handlers.length > 0 ? ["'unsafe-hashes'", ...handlers] : []), "'wasm-unsafe-eval'", 'https://binaries.soliditylang.org'],
    'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    'font-src': ["'self'", 'data:', 'https://fonts.gstatic.com'],
    'img-src': ["'self'", 'data:', 'blob:', 'https:'],
    'media-src': ["'self'"],
    'connect-src': ["'self'", 'https://ethereum-sepolia.blockpi.network', 'https://www.googleapis.com', 'https://binaries.soliditylang.org'],
    'worker-src': ["'self'", 'blob:'],
    'frame-src': ["'self'", 'https://w.soundcloud.com'],
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': ["'self'"]
  }
  return Object.entries(directives).map(([name, sources]) => `${name} ${[...new Set(sources)].join(' ')}`).join('; ')
}

export function applyFileCsp (file: string) {
  let cached: { version: string, header: string } | undefined
  const currentPolicy = () => {
    try {
      const { mtimeMs, size } = fs.statSync(file)
      const version = `${mtimeMs}:${size}`
      if (cached?.version !== version) {
        cached = { version, header: contentSecurityPolicy(inlineScriptHashes(fs.readFileSync(file, 'utf8'))) }
      }
      return cached.header
    } catch {
      return contentSecurityPolicy()
    }
  }
  return (res: Response) => {
    res.setHeader(cspHeaderName(), currentPolicy())
  }
}

export function fileCsp (file: string) {
  const applyCsp = applyFileCsp(file)
  return (req: Request, res: Response, next: NextFunction) => {
    applyCsp(res)
    next()
  }
}

export function angularClientCsp (indexFile: string = path.resolve('frontend/dist/frontend/index.html')) {
  return fileCsp(indexFile)
}

export function exposeErrorDetails (env: NodeJS.ProcessEnv = process.env): boolean {
  return !isProduction(env)
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
