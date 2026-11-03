/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
import { QuantityModel } from '../models/quantity'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { findOwnBasket, ownBasketIds } from '../lib/basketOwnership'

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

    const ownBasket = basketIds.length > 0 ? await findOwnBasket(req, basketIds[basketIds.length - 1]) : null
    if (ownBasket == null || !basketIds.every(basketId => Number(basketId) === ownBasket.id)) {
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
    } else {
      const basketItem = {
        ProductId: productIds[productIds.length - 1],
        BasketId: ownBasket.id,
        quantity: quantities[quantities.length - 1]
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
      if (item == null) {
        next()
        return
      }
      if (await findOwnBasket(req, item.BasketId) == null || (req.body.BasketId !== undefined && Number(req.body.BasketId) !== item.BasketId)) {
        res.status(403).json({ status: 'error', message: 'Access to this basket is forbidden.' })
        return
      }

      if (req.body.quantity) {
        void quantityCheck(req, res, next, item.ProductId, req.body.quantity)
      } else {
        next()
      }
    } catch (error) {
      next(error)
    }
  }
}

export function ensureBasketItemOwnership () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
      if (item == null) {
        next()
        return
      }
      if (await findOwnBasket(req, item.BasketId) == null) {
        res.status(403).json({ status: 'error', message: 'Access to this basket is forbidden.' })
        return
      }
      next()
    } catch (error) {
      next(error)
    }
  }
}

export function listOwnBasketItems () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const items = await BasketItemModel.findAll({ where: { BasketId: await ownBasketIds(req) } })
      res.json({ status: 'success', data: items })
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
