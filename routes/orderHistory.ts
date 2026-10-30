/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'
import { orderReceiptPath } from './order'

const ORDER_ID_PATTERN = /^[0-9a-f]{4}-[0-9a-f]{16}$/

export function orderHistory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''))
    if (loggedInUser?.data?.email && loggedInUser.data.id) {
      const email = loggedInUser.data.email
      const updatedEmail = email.replace(/[aeiou]/gi, '*')
      const order = await ordersCollection.find({ email: updatedEmail })
      res.status(200).json({ status: 'success', data: order })
    } else {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}

export function allOrders () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const order = await ordersCollection.find()
    res.status(200).json({ status: 'success', data: order.reverse() })
  }
}

export function toggleDeliveryStatus () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const deliveryStatus = !req.body.deliveryStatus
    const eta = deliveryStatus ? '0' : '1'
    await ordersCollection.update({ _id: req.params.id }, { $set: { delivered: deliveryStatus, eta } })
    res.status(200).json({ status: 'success' })
  }
}

export function orderReceipt () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    const email = loggedInUser?.data?.email
    if (!email) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }
    const orderId = String(req.params.orderId)
    if (!ORDER_ID_PATTERN.test(orderId) || orderId.slice(0, 4) !== security.hash(email).slice(0, 4)) {
      res.status(404).json({ status: 'error', message: 'Not found' })
      return
    }
    const orders = await ordersCollection.find({ orderId, email: email.replace(/[aeiou]/gi, '*') })
    if (orders.length === 0) {
      res.status(404).json({ status: 'error', message: 'Not found' })
      return
    }
    res.type('application/pdf')
    res.sendFile(orderReceiptPath(email, orderId), (err?: Error) => {
      if (err && !res.headersSent) {
        res.status(404).json({ status: 'error', message: 'Not found' })
      }
    })
  }
}
