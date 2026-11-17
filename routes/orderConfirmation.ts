/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import fs from 'node:fs'
import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export const ordersDirectory = path.resolve('orders')

export function serveOrderConfirmation () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = req.cookies?.token ?? utils.jwtFrom(req)
    const loggedInUser = security.verify(token) ? security.authenticatedUsers.get(token) : undefined
    const email = loggedInUser?.data?.email
    if (!email) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }

    const orderId = req.params.id
    if (!/^[0-9a-f]{4}-[0-9a-f]{16}$/.test(orderId) || !orderId.startsWith(security.hash(email).slice(0, 4))) {
      res.status(404).json({ status: 'error', message: 'Order not found' })
      return
    }

    const order = await ordersCollection.findOne({ orderId })
    const file = path.join(ordersDirectory, `order_${orderId}.pdf`)
    if (!order || order.email !== email.replace(/[aeiou]/gi, '*') || !fs.existsSync(file)) {
      res.status(404).json({ status: 'error', message: 'Order not found' })
      return
    }

    res.sendFile(file)
  }
}
