/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
import { QuantityModel } from '../models/quantity'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

interface RequestWithRawBody extends Request {
  rawBody: string
}

export function addBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const result = utils.parseJsonCustom((req as RequestWithRawBody).rawBody)
    const keyCounts: Record<string, number> = {}
    for (const { key } of result) {
      keyCounts[key] = (keyCounts[key] ?? 0) + 1
    }
    if (['ProductId', 'BasketId', 'quantity'].some(key => keyCounts[key] > 1)) {
      res.status(400).json({ error: 'Duplicate parameters are not allowed' })
      return
    }

    const user = security.authenticatedUsers.from(req)
    if (!isOwnBasket(user, req.body.BasketId)) {
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
      return
    }

    const basketItem = {
      ProductId: req.body.ProductId,
      BasketId: user?.bid,
      quantity: req.body.quantity
    }

    const basketItemInstance = BasketItemModel.build(basketItem)
    try {
      const addedBasketItem = await basketItemInstance.save()
      res.json({ status: 'success', data: addedBasketItem })
    } catch (error) {
      next(error)
    }
  }
}

export function quantityCheckBeforeBasketItemAddition () {
  return (req: Request, res: Response, next: NextFunction) => {
    void quantityCheck(req, res, next, req.body.ProductId, req.body.quantity).catch((error: Error) => {
      next(error)
    })
  }
}
export function ensureBasketItemOwnership () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
      if (item != null && !isOwnBasket(security.authenticatedUsers.from(req), item.BasketId)) {
        res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
        return
      }
      next()
    } catch (error) {
      next(error)
    }
  }
}

export function quantityCheckBeforeBasketItemUpdate () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
      if (item == null) {
        throw new Error('No such item found!')
      }
      const user = security.authenticatedUsers.from(req)
      if (!isOwnBasket(user, item.BasketId) || (req.body.BasketId !== undefined && !isOwnBasket(user, req.body.BasketId))) {
        res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
        return
      }
      if (req.body.quantity !== undefined) {
        await quantityCheck(req, res, next, item.ProductId, req.body.quantity)
      } else {
        next()
      }
    } catch (error) {
      next(error)
    }
  }
}

function isOwnBasket (user: { bid?: number } | undefined, basketId: unknown) {
  if (user?.bid === undefined) {
    return false
  }
  if (typeof basketId === 'number') {
    return Number.isInteger(basketId) && basketId === Number(user.bid)
  }
  if (typeof basketId === 'string') {
    return /^\d+$/.test(basketId) && Number(basketId) === Number(user.bid)
  }
  return false
}

async function quantityCheck (req: Request, res: Response, next: NextFunction, id: number, quantity: unknown) {
  if (typeof quantity !== 'number' || !Number.isInteger(quantity) || quantity < 1) {
    res.status(400).json({ error: 'Quantity must be a positive integer' })
    return
  }

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
