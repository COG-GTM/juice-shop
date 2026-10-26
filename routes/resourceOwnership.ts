/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
import { BasketModel } from '../models/basket'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'

const forbidden = (res: Response) => res.status(403).json({ error: 'Not allowed' })

const callerOf = (req: Request): { id?: number, role?: string } | undefined => security.verifiedTokenData(req)

const isAdmin = (caller?: { role?: string }) => caller?.role === security.roles.admin

export function ownUserOrAdmin () {
  return (req: Request, res: Response, next: NextFunction) => {
    const caller = callerOf(req)
    if (isAdmin(caller) || (caller?.id != null && String(caller.id) === req.params.id)) {
      next()
    } else {
      forbidden(res)
    }
  }
}

export function ownBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const caller = callerOf(req)
    if (caller?.id == null) {
      return forbidden(res)
    }
    const item = await BasketItemModel.findByPk(req.params.id)
    const basket = item?.BasketId != null ? await BasketModel.findOne({ where: { id: item.BasketId, UserId: caller.id } }) : null
    if (basket == null) {
      return forbidden(res)
    }
    next()
  }
}

export function basketItemQuantityOnly () {
  return (req: Request, res: Response, next: NextFunction) => {
    const otherFields = Object.keys(req.body ?? {}).filter(key => key !== 'quantity' && key !== 'UserId')
    if (otherFields.length > 0) {
      return res.status(400).json({ error: 'Only the quantity of a basket item can be updated.' })
    }
    next()
  }
}

export function ownFeedbackOrAdmin () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const caller = callerOf(req)
    if (isAdmin(caller)) {
      return next()
    }
    const feedback = caller?.id != null ? await FeedbackModel.findByPk(req.params.id) : null
    if (feedback?.UserId == null || feedback.UserId !== caller?.id) {
      return forbidden(res)
    }
    next()
  }
}
