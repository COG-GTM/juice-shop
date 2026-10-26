/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AddressModel } from '../models/address'
import { BasketModel } from '../models/basket'
import { BasketItemModel } from '../models/basketitem'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'

function forbidden (res: Response) {
  res.status(403).json({ error: 'Malicious activity detected' })
}

function isAdminOrOwner (user: { id?: number, role?: string } | undefined, ownerId: number | null | undefined) {
  if (user == null) return false
  return user.role === security.roles.admin || (ownerId != null && ownerId === user.id)
}

export function checkUserAccess () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (isAdminOrOwner(security.verifiedUserFrom(req), Number(req.params.id))) {
      next()
    } else {
      forbidden(res)
    }
  }
}

export function checkFeedbackOwnership () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const feedback = await FeedbackModel.findByPk(req.params.id)
    if (feedback == null) {
      next()
    } else if (isAdminOrOwner(security.verifiedUserFrom(req), feedback.UserId)) {
      next()
    } else {
      forbidden(res)
    }
  }
}

export function checkBasketItemOwnership () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const item = await BasketItemModel.findByPk(req.params.id)
    if (item == null) {
      next()
      return
    }
    const basket = item.BasketId != null ? await BasketModel.findByPk(item.BasketId) : null
    const user = security.verifiedUserFrom(req)
    if (user != null && basket?.UserId != null && basket.UserId === user.id) {
      next()
    } else {
      forbidden(res)
    }
  }
}

export function checkAddressOwnership () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.verifiedUserFrom(req)
    const address = user?.id != null ? await AddressModel.findOne({ where: { id: req.params.id, UserId: user.id } }) : null
    if (address != null) {
      next()
    } else {
      forbidden(res)
    }
  }
}
