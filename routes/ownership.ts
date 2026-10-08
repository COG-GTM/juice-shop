/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AddressModel } from '../models/address'
import { BasketModel } from '../models/basket'
import { BasketItemModel } from '../models/basketitem'
import { ComplaintModel } from '../models/complaint'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

interface Requester { id: number, role?: string }

function requesterFrom (req: Request): Requester | undefined {
  const token = utils.jwtFrom(req)
  const decoded = security.verify(token) && security.decode(token)
  const id = decoded?.data?.id
  return typeof id === 'number' ? { id, role: decoded.data.role } : undefined
}

function isAdmin (requester: Requester) {
  return requester.role === security.roles.admin
}

function unauthorized (res: Response) {
  return res.status(401).json({ status: 'error', message: 'Unauthorized' })
}

function forbidden (res: Response) {
  return res.status(403).json({ status: 'error', message: 'Malicious activity detected.' })
}

export function getOwnBasketItems () {
  return async (req: Request, res: Response) => {
    const requester = requesterFrom(req)
    if (requester == null) return unauthorized(res)
    const baskets = await BasketModel.findAll({ where: { UserId: requester.id }, attributes: ['id'] })
    const basketItems = await BasketItemModel.findAll({ where: { BasketId: baskets.map(basket => basket.id) } })
    res.json({ status: 'success', data: basketItems })
  }
}

export function checkBasketItemOwnership () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const requester = requesterFrom(req)
    if (requester == null) return unauthorized(res)
    const item = await BasketItemModel.findByPk(req.params.id)
    if (item == null) return next()
    const basket = item.BasketId != null ? await BasketModel.findOne({ where: { id: item.BasketId, UserId: requester.id } }) : null
    if (basket == null) return forbidden(res)
    next()
  }
}

export function checkAddressOwnership () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const requester = requesterFrom(req)
    if (requester == null) return unauthorized(res)
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: requester.id } })
    if (address == null) {
      return res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
    req.body.UserId = requester.id
    next()
  }
}

export function checkFeedbackDeletion () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const requester = requesterFrom(req)
    if (requester == null) return unauthorized(res)
    const feedback = await FeedbackModel.findByPk(req.params.id)
    if (feedback == null || isAdmin(requester) || (feedback.UserId != null && feedback.UserId === requester.id)) return next()
    forbidden(res)
  }
}

export function checkUserAccess () {
  return (req: Request, res: Response, next: NextFunction) => {
    const requester = requesterFrom(req)
    if (requester == null) return unauthorized(res)
    if (isAdmin(requester) || String(requester.id) === req.params.id) return next()
    forbidden(res)
  }
}

export function getOwnComplaints () {
  return async (req: Request, res: Response) => {
    const requester = requesterFrom(req)
    if (requester == null) return unauthorized(res)
    const complaints = await ComplaintModel.findAll(isAdmin(requester) ? {} : { where: { UserId: requester.id } })
    res.json({ status: 'success', data: complaints })
  }
}
