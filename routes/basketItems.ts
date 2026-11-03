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
    const rawBody = (req as RequestWithRawBody).rawBody
    const keys = typeof rawBody === 'string' ? utils.parseJsonCustom(rawBody).map((entry: { key: string }) => entry.key) : []
    if (['ProductId', 'BasketId', 'quantity'].some(key => keys.filter((k: string) => k === key).length > 1)) {
      res.status(400).json({ error: 'Duplicate keys in request body' })
      return
    }

    const user = security.authenticatedUsers.from(req)
    const requestedBasketId = req.body.BasketId
    if (!user?.bid || (requestedBasketId !== undefined && requestedBasketId !== 'undefined' && Number(requestedBasketId) !== Number(user.bid))) {
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
      return
    }

    const basketItem = {
      ProductId: req.body.ProductId,
      BasketId: user.bid,
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

export function checkBasketItemOwnership () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
      if (item == null) {
        next()
        return
      }
      const user = security.authenticatedUsers.from(req)
      if (!user?.bid || item.BasketId == null || Number(item.BasketId) !== Number(user.bid)) {
        res.status(403).json({ error: 'Basket item does not belong to your basket' })
        return
      }
      next()
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
export function quantityCheckBeforeBasketItemUpdate () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
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
