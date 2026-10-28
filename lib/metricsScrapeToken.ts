/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import fs from 'node:fs'
import { type Request, type Response } from 'express'
import logger from './logger'
import { getErrorMessage } from './utils'

export const MIN_SCRAPE_TOKEN_LENGTH = 32

export function loadMetricsScrapeToken (env: NodeJS.ProcessEnv = process.env): string | undefined {
  let token = env.METRICS_SCRAPE_TOKEN
  if (!token && env.METRICS_SCRAPE_TOKEN_FILE) {
    try {
      token = fs.readFileSync(env.METRICS_SCRAPE_TOKEN_FILE, 'utf8')
    } catch (error) {
      logger.warn(`Could not read METRICS_SCRAPE_TOKEN_FILE: ${getErrorMessage(error)}`)
      return undefined
    }
  }
  token = token?.trim()
  if (!token) {
    logger.info('METRICS_SCRAPE_TOKEN is not set, so /metrics is disabled')
    return undefined
  }
  if (token.length < MIN_SCRAPE_TOKEN_LENGTH) {
    logger.warn(`METRICS_SCRAPE_TOKEN must be at least ${MIN_SCRAPE_TOKEN_LENGTH} characters, so /metrics is disabled`)
    return undefined
  }
  return token
}

export function hasValidScrapeToken (req: Request, expectedToken: string) {
  const match = /^Bearer (\S+)$/i.exec(req.headers.authorization ?? '')
  if (match == null) return false
  return crypto.timingSafeEqual(sha256(match[1]), sha256(expectedToken))
}

export function authorizeMetricsScrape (req: Request, res: Response, expectedToken: string | undefined) {
  if (expectedToken === undefined) {
    res.status(404).end()
    return false
  }
  if (!hasValidScrapeToken(req, expectedToken)) {
    res.set('WWW-Authenticate', 'Bearer realm="metrics"')
    res.status(401).end()
    return false
  }
  return true
}

function sha256 (value: string) {
  return crypto.createHash('sha256').update(value).digest()
}
