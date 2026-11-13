/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'
import { orderConfirmationFile } from './order'

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

export function orderConfirmation () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const userId = security.authenticatedUsers.from(req)?.data?.id
    const orderId = req.params.id
    if (!userId || !/^[0-9a-f]{4}-[0-9a-f]{16}$/.test(orderId)) {
      res.status(404).json({ status: 'error', message: 'Order confirmation not found' })
      return
    }
    res.sendFile(orderConfirmationFile(userId, orderId), (err) => {
      if (err && !res.headersSent) {
        res.status(404).json({ status: 'error', message: 'Order confirmation not found' })
      }
    })
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
