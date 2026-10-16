/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export const orderConfirmationsDirectory = 'orders'
const orderIdPattern = /^[0-9a-f]{4}-[0-9a-f]{16}$/

export function orderConfirmationPath (userId: number | undefined, orderId: string) {
  return path.resolve(orderConfirmationsDirectory, String(userId ?? 'anonymous'), `order_${orderId}.pdf`)
}

function isValidToken (token: string) {
  const exp = security.decode(token)?.exp
  return security.verify(token) && (typeof exp !== 'number' || exp * 1000 > Date.now())
}

export function retrieveOrderConfirmation () {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = utils.unquote(utils.jwtFrom(req) ?? req.cookies?.token ?? '')
    const userId = isValidToken(token) ? security.authenticatedUsers.get(token)?.data?.id : undefined
    if (!userId) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }

    const orderId = req.params.orderId
    const pdfPath = orderIdPattern.test(orderId) ? orderConfirmationPath(userId, orderId) : undefined
    if (!pdfPath || !fs.existsSync(pdfPath)) {
      res.status(404).json({ status: 'error', message: 'Order confirmation not found' })
      return
    }

    res.set('Cache-Control', 'private, no-store')
    res.sendFile(pdfPath, (err) => {
      if (err) next(err)
    })
  }
}
