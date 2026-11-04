/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
import { BasketModel } from '../models/basket'
import { QuantityModel } from '../models/quantity'
import * as challengeUtils from '../lib/challengeUtils'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

interface RequestWithRawBody extends Request {
  rawBody: string
}

export function addBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const result = utils.parseJsonCustom((req as RequestWithRawBody).rawBody)
    const productIds = []
    const basketIds = []
    const quantities = []

    for (let i = 0; i < result.length; i++) {
      if (result[i].key === 'ProductId') {
        productIds.push(result[i].value)
      } else if (result[i].key === 'BasketId') {
        basketIds.push(result[i].value)
      } else if (result[i].key === 'quantity') {
        quantities.push(result[i].value)
      }
    }

    if (basketIds.length !== 1 || productIds.length > 1 || quantities.length > 1) {
      res.status(400).json({ status: 'error', message: 'Invalid BasketItem' })
      return
    }

    const user = security.authenticatedUsers.from(req)
    if (!user || !(await isOwnBasket(user.data.id, req.body.BasketId))) {
      res.status(403).json({ status: 'error', message: 'Invalid BasketId' })
      return
    }

    const basketItemInstance = BasketItemModel.build({
      ProductId: req.body.ProductId,
      BasketId: req.body.BasketId,
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

export function listOwnBasketItems () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }
    const baskets = await BasketModel.findAll({ where: { UserId: user.data.id }, attributes: ['id'] })
    const items = await BasketItemModel.findAll({ where: { BasketId: baskets.map(basket => basket.id) } })
    res.json({ status: 'success', data: items })
  }
}

export function ensureBasketItemOwnership () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }
    const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
    if (item == null) {
      res.status(404).json({ status: 'error', message: 'Not found' })
      return
    }
    if (!(await isOwnBasket(user.data.id, item.BasketId))) {
      res.status(403).json({ status: 'error', message: 'Forbidden' })
      return
    }
    next()
  }
}

async function isOwnBasket (userId: number | undefined, basketId: unknown) {
  if (userId === undefined || basketId === undefined || basketId === null) return false
  const id = Number(basketId)
  if (!Number.isInteger(id)) return false
  const basket = await BasketModel.findOne({ where: { id, UserId: userId } })
  return basket != null
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
      if (req.body.quantity) {
        if (item == null) {
          throw new Error('No such item found!')
        }
        void quantityCheck(req, res, next, item.ProductId, req.body.quantity)
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
