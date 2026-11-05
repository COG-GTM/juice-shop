/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export const orderConfirmationsDir = path.resolve('data/orders')

const orderIdPattern = /^[0-9a-f]{4}-[0-9a-f]{16}$/

export function serveOrderConfirmation () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = utils.jwtFrom(req) ?? req.cookies?.token
    const loggedInUser = security.authenticatedUsers.get(token)
    const email = loggedInUser?.data?.email
    if (!email) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }

    const orderId = req.params.id
    if (!orderIdPattern.test(orderId)) {
      res.status(404).json({ status: 'error', message: 'Order not found' })
      return
    }

    const order = await ordersCollection.findOne({ orderId })
    const isOwner = order?.email === email.replace(/[aeiou]/gi, '*') && orderId.startsWith(security.hash(email).slice(0, 4))
    if (!isOwner) {
      res.status(404).json({ status: 'error', message: 'Order not found' })
      return
    }

    res.sendFile(path.join(orderConfirmationsDir, `order_${orderId}.pdf`), (err) => {
      if (err) {
        next(err)
      }
    })
  }
}
