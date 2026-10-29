/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
import { QuantityModel } from '../models/quantity'
import * as security from '../lib/insecurity'
import { ownsBasket } from './basket'

export function addBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const { ProductId, BasketId, quantity } = req.body ?? {}
    if (!await ownsBasket(req, BasketId)) {
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
      return
    }
    const basketItemInstance = BasketItemModel.build({ ProductId, BasketId: Number(BasketId), quantity })
    try {
      const addedBasketItem = await basketItemInstance.save()
      res.json({ status: 'success', data: addedBasketItem })
    } catch (error) {
      next(error)
    }
  }
}

export function ensureBasketItemOwnership () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
    if (item != null && !await ownsBasket(req, item.BasketId)) {
      res.status(403).json({ status: 'error', message: 'Access to this basket item is not allowed' })
      return
    }
    next()
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
      if ((item != null && !await ownsBasket(req, item.BasketId)) || (req.body.BasketId !== undefined && !await ownsBasket(req, req.body.BasketId))) {
        res.status(403).json({ status: 'error', message: 'Access to this basket item is not allowed' })
        return
      }
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
