/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'

export const orderConfirmationsFolder = 'orders/'

export function orderConfirmation () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (!loggedInUser?.data?.id) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }
    const orderId = req.params.id
    if (!/^[a-z0-9]+-[a-z0-9]+$/i.test(orderId)) {
      res.status(400).json({ status: 'error', message: 'Invalid order id' })
      return
    }
    const order = await ordersCollection.findOne({ orderId })
    if (!order || order.UserId !== loggedInUser.data.id) {
      res.status(404).json({ status: 'error', message: 'Order not found' })
      return
    }
    res.sendFile(path.resolve(orderConfirmationsFolder, `order_${orderId}.pdf`), (err) => {
      if (err) {
        next(err)
      }
    })
  }
}
