/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'
import { orderConfirmationsDir } from './order'

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

export function orderConfirmation () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    const email = loggedInUser?.data?.email
    const orderId = req.params.id
    if (!email) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }
    if (typeof orderId !== 'string' || !/^[0-9a-f]{4}-[0-9a-f]{16}$/.test(orderId) || !orderId.startsWith(security.hash(email).slice(0, 4))) {
      res.status(404).json({ status: 'error', message: 'Order not found' })
      return
    }
    const order = await ordersCollection.findOne({ orderId, email: email.replace(/[aeiou]/gi, '*') })
    const customerDir = path.resolve(orderConfirmationsDir, security.hash(email))
    const pdfFile = path.resolve(customerDir, `order_${orderId}.pdf`)
    if (!order || !pdfFile.startsWith(customerDir + path.sep) || !fs.existsSync(pdfFile)) {
      res.status(404).json({ status: 'error', message: 'Order not found' })
      return
    }
    res.type('application/pdf')
    res.sendFile(pdfFile)
  }
}
