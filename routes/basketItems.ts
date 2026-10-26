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

    const user = security.authenticatedUsers.from(req)
    if (user && basketIds[0] && basketIds[0] !== 'undefined' && Number(user.bid) != Number(basketIds[0])) { // eslint-disable-line eqeqeq
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
    } else {
      const basketItem = {
        ProductId: productIds[productIds.length - 1],
        BasketId: basketIds[basketIds.length - 1],
        quantity: quantities[quantities.length - 1]
      }
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && basketItem.BasketId && basketItem.BasketId !== 'undefined' && user.bid != basketItem.BasketId }) // eslint-disable-line eqeqeq

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

async function findOwnBasketItem (req: Request, userId: number) {
  const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
  if (item?.BasketId == null) {
    return null
  }
  const basket = await BasketModel.findOne({ where: { id: item.BasketId, UserId: userId } })
  return basket != null ? item : null
}

export function checkBasketItemOwnership () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = security.authenticatedUsers.from(req)
      if (user?.data?.id == null) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }
      if (await findOwnBasketItem(req, user.data.id) == null) {
        res.status(403).json({ error: 'Not allowed' })
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
      const user = security.authenticatedUsers.from(req)
      if (user?.data?.id == null) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }
      const baskets = await BasketModel.findAll({ where: { UserId: user.data.id }, attributes: ['id'] })
      const items = await BasketItemModel.findAll({ where: { BasketId: baskets.map(({ id }) => id) } })
      res.json({ status: 'success', data: items })
    } catch (error) {
      next(error)
    }
  }
}

export function quantityCheckBeforeBasketItemUpdate () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = security.authenticatedUsers.from(req)
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && req.body.BasketId && user.bid != req.body.BasketId }) // eslint-disable-line eqeqeq
      if (user?.data?.id == null) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }
      const item = await findOwnBasketItem(req, user.data.id)
      if (item == null) {
        res.status(403).json({ error: 'Not allowed' })
        return
      }
      const rawQuantity = req.body?.quantity
      const quantity = typeof rawQuantity === 'string' && /^-?\d+$/.test(rawQuantity) ? Number(rawQuantity) : rawQuantity
      const otherFields = Object.keys(req.body ?? {}).filter(key => key !== 'quantity' && key !== 'UserId')
      if (otherFields.length > 0 || !Number.isSafeInteger(quantity)) {
        res.status(400).json({ error: 'Only the quantity of a basket item can be updated.' })
        return
      }
      req.body = { quantity }
      if (quantity) {
        await quantityCheck(req, res, next, item.ProductId, quantity)
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
