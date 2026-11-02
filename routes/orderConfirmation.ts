/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import jwt from 'jsonwebtoken'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const orderIdPattern = /^[a-f0-9]{4}-[a-f0-9]{16}$/

export const orderConfirmationDirectory = (email: string) => path.resolve('orders', security.hash(email))

function authenticatedEmailFrom (req: Request): string | undefined {
  const token = utils.jwtFrom(req) ?? req.cookies?.token
  if (!token) return undefined
  try {
    const decoded = jwt.verify(utils.unquote(token), security.publicKey, { algorithms: ['RS256'] }) as { data?: { email?: string } }
    return decoded?.data?.email || undefined
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
