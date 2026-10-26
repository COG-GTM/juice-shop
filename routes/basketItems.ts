/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
import { BasketModel } from '../models/basket'
import { QuantityModel } from '../models/quantity'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

type AuthenticatedUser = ReturnType<typeof security.authenticatedUsers.from>

export function addBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const basketId = await ownBasketId(user)
    const requestedBasketId = req.body.BasketId
    const hasRequestedBasketId = requestedBasketId !== undefined && requestedBasketId !== null && requestedBasketId !== '' && requestedBasketId !== 'undefined'
    challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user != null && hasRequestedBasketId && Number(requestedBasketId) !== basketId })

    if (basketId == null || (hasRequestedBasketId && Number(requestedBasketId) !== basketId)) {
      res.status(401).json({ error: 'Invalid BasketId' })
      return
    }

    const basketItemInstance = BasketItemModel.build({
      ProductId: req.body.ProductId,
      BasketId: basketId,
      quantity: req.body.quantity
    })
    try {
      const addedBasketItem = await basketItemInstance.save()
      res.json({ status: 'success', data: addedBasketItem })
    } catch (error) {
      next(error)
    }
  }
}

async function ownBasketId (user: AuthenticatedUser) {
  if (user?.data?.id == null) {
    return undefined
  }
  if (user.bid != null && await ownsBasket(user, Number(user.bid))) {
    return Number(user.bid)
  }
  const basket = await BasketModel.findOne({ where: { UserId: user.data.id } })
  return basket?.id
}

async function ownsBasket (user: AuthenticatedUser, basketId: number | null | undefined) {
  if (user?.data?.id == null || basketId == null) {
    return false
  }
  return await BasketModel.findOne({ where: { id: basketId, UserId: user.data.id } }) != null
}

export function quantityCheckBeforeBasketItemAddition () {
  return (req: Request, res: Response, next: NextFunction) => {
    void quantityCheck(req, res, next, req.body.ProductId, req.body.quantity).catch((error: Error) => {
      next(error)
    })
  }
}
export function quantityCheckBeforeBasketItemUpdate () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
      const user = security.authenticatedUsers.from(req)
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && req.body.BasketId && user.bid != req.body.BasketId }) // eslint-disable-line eqeqeq
      if (item == null || !(await ownsBasket(user, item.BasketId))) {
        res.status(403).json({ error: 'Not allowed' })
        return
      }
      if (req.body.quantity) {
        await quantityCheck(req, res, next, item.ProductId, req.body.quantity)
      } else {
        next()
      }
    } catch (error) {
      next(error)
    }
  }
}

async function quantityCheck (req: Request, res: Response, next: NextFunction, id: number, quantity: number) {
  const product = await QuantityModel.findOne({ where: { ProductId: id } })
  if (product == null) {
    throw new Error('No such product found!')
  }

  // is product limited per user and order, except if user is deluxe?
  if (!product.limitPerUser || (product.limitPerUser && product.limitPerUser >= quantity) || security.isDeluxe(req)) {
    if (product.quantity >= quantity) { // enough in stock?
      next()
    } else {
      res.status(400).json({ error: res.__('We are out of stock! Sorry for the inconvenience.') })
    }
  } else {
    res.status(400).json({ error: res.__('You can order only up to {{quantity}} items of this product.', { quantity: product.limitPerUser.toString() }) })
  }
}
