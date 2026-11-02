/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const orderIdPattern = /^[a-f0-9]{4}-[a-f0-9]{16}$/

export const orderConfirmationDirectory = (email: string) => path.resolve('orders', security.hash(email))

function verifiedRs256Payload (token: string): { data?: { email?: string }, exp?: number } | undefined {
  const parts = token.split('.')
  if (parts.length !== 3) return undefined
  const [header, payload, signature] = parts
  const { alg } = JSON.parse(Buffer.from(header, 'base64url').toString('utf8'))
  if (alg !== 'RS256') return undefined
  const valid = crypto.verify('RSA-SHA256', Buffer.from(`${header}.${payload}`), security.publicKey, Buffer.from(signature, 'base64url'))
  if (!valid) return undefined
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))
  if (typeof claims.exp === 'number' && claims.exp * 1000 < Date.now()) return undefined
  return claims
}

function authenticatedEmailFrom (req: Request): string | undefined {
  const token = utils.jwtFrom(req) ?? req.cookies?.token
  if (!token) return undefined
  try {
    return verifiedRs256Payload(utils.unquote(token))?.data?.email || undefined
  } catch {
    return undefined
  }
}

export function serveOrderConfirmation () {
  return (req: Request, res: Response, next: NextFunction) => {
    const email = authenticatedEmailFrom(req)
    if (!email) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }
    const orderId = req.params.id
    if (!orderIdPattern.test(orderId)) {
      res.status(404).json({ status: 'error', message: 'Order confirmation not found' })
      return
    }
    const file = path.join(orderConfirmationDirectory(email), `order_${orderId}.pdf`)
    res.sendFile(file, (err) => {
      if (err && !res.headersSent) {
        res.status(404).json({ status: 'error', message: 'Order confirmation not found' })
      }
    })
  }
}
