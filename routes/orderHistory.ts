/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import fs from 'node:fs'
import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'
import { orderConfirmationsFolder } from './order'

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
    if (!loggedInUser?.data?.email || !loggedInUser.data.id) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }
    if (!/^[a-f0-9]{4}-[a-f0-9]{16}$/.test(orderId)) {
      res.status(404).json({ status: 'error', message: 'Order not found' })
      return
    }
    const order = await ordersCollection.findOne({
      orderId,
      UserId: loggedInUser.data.id,
      email: loggedInUser.data.email.replace(/[aeiou]/gi, '*')
    })
    const pdfFile = path.resolve(orderConfirmationsFolder, `order_${orderId}.pdf`)
    if (!order || !fs.existsSync(pdfFile)) {
      res.status(404).json({ status: 'error', message: 'Order not found' })
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
