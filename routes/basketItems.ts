/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
import { BasketModel } from '../models/basket'
import { QuantityModel } from '../models/quantity'

import * as security from '../lib/insecurity'

async function ownBasketIdsOf (req: Request): Promise<number[] | undefined> {
  const user = security.authenticatedUsers.from(req)
  if (!user?.data?.id) {
    return undefined
  }
  const baskets = await BasketModel.findAll({ where: { UserId: user.data.id } })
  return baskets.map(basket => basket.id)
}

async function isOwnBasketItem (req: Request, item: BasketItemModel) {
  const basketIds = await ownBasketIdsOf(req)
  return basketIds !== undefined && item.BasketId != null && basketIds.includes(item.BasketId)
}

function denyAccess (res: Response) {
  res.status(403).json({ status: 'error', error: 'Basket item does not belong to your basket' })
}

export function addBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const basketId = user?.bid ?? (await ownBasketIdsOf(req))?.[0]
    if (!basketId) {
      res.status(401).json({ status: 'error', error: 'Invalid BasketId' })
      return
    }
    const basketItem = {
      ProductId: req.body.ProductId,
      BasketId: basketId,
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

export function retrieveOwnBasketItems () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const basketIds = await ownBasketIdsOf(req)
      if (basketIds === undefined) {
        res.status(401).json({ status: 'error', error: 'Unauthorized' })
        return
      }
      const items = await BasketItemModel.findAll({ where: { BasketId: basketIds } })
      res.json({ status: 'success', data: items })
    } catch (error) {
      next(error)
    }
  }
}

export function checkBasketItemOwnership () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
      if (item != null && !(await isOwnBasketItem(req, item))) {
        denyAccess(res)
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
      if (item != null && !(await isOwnBasketItem(req, item))) {
        denyAccess(res)
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
