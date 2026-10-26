/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'
import { ORDER_CONFIRMATIONS_DIR } from './order'

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
    const loggedInUser = security.authenticatedUsers.from(req)
    const orderId = req.params.id
    if (loggedInUser?.data?.id === undefined || !/^[0-9a-f]{4}-[0-9a-f]{16}$/.test(orderId)) {
      res.status(404).json({ status: 'error', message: 'Order confirmation not found' })
      return
    }
    const orders = await ordersCollection.find({ orderId, UserId: loggedInUser.data.id })
    if (orders.length === 0) {
      res.status(404).json({ status: 'error', message: 'Order confirmation not found' })
      return
    }
    const pdfFile = path.resolve(ORDER_CONFIRMATIONS_DIR, path.basename(`order_${orders[0].orderId}.pdf`))
    if (!fs.existsSync(pdfFile)) {
      res.status(404).json({ status: 'error', message: 'Order confirmation not found' })
      return
    }
    res.sendFile(pdfFile)
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
