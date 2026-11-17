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
    const orderId = req.params.orderId
    if (!loggedInUser?.data?.email || !/^[0-9a-f]{4}-[0-9a-f]{16}$/.test(orderId)) {
      res.status(403).json({ error: 'Forbidden' })
      return
    }
    const email = loggedInUser.data.email
    const order = await ordersCollection.findOne({ orderId, email: email.replace(/[aeiou]/gi, '*') })
    if (!order || !orderId.startsWith(security.hash(email).slice(0, 4))) {
      res.status(404).json({ error: 'Order not found' })
      return
    }
    const pdfFile = path.join(orderConfirmationsDir, `order_${orderId}.pdf`)
    if (!fs.existsSync(pdfFile)) {
      res.status(404).json({ error: 'Order confirmation not found' })
      return
    }
    res.sendFile(pdfFile, { headers: { 'Content-Type': 'application/pdf', 'Cache-Control': 'no-store' } })
  }
}
