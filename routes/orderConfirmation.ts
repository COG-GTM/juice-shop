/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'

export const orderConfirmationsDir = path.resolve('data/orders')

const orderIdPattern = /^[a-f0-9]{4}-[a-f0-9]{16}$/

export function orderConfirmationPath (userId: number | string, orderId: string) {
  return path.join(orderConfirmationsDir, String(userId), `order_${orderId}.pdf`)
}

export function serveOrderConfirmation () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const userId = user?.data?.id
    if (userId === undefined || userId === null) {
      res.status(401)
      next(new Error('Unauthorized'))
      return
    }

    const orderId = req.params.orderId
    if (!orderIdPattern.test(orderId)) {
      res.status(400)
      next(new Error('Invalid order id'))
      return
    }

    const file = orderConfirmationPath(userId, orderId)
    if (!fs.existsSync(file)) {
      res.status(404)
      next(new Error('Order confirmation not found'))
      return
    }

    res.sendFile(file)
  }
}
