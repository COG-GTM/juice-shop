/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
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
    const basketIds: Array<string | number> = []
    const seenKeys = new Set<string>()
    let hasDuplicateKey = false

    for (let i = 0; i < result.length; i++) {
      const key = result[i].key
      if (key === 'ProductId' || key === 'BasketId' || key === 'quantity') {
        hasDuplicateKey = hasDuplicateKey || seenKeys.has(key)
        seenKeys.add(key)
        if (key === 'BasketId') {
          basketIds.push(result[i].value)
        }
      }
    }

    const user = security.authenticatedUsers.from(req)
    challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && basketIds.length > 1 && basketIds.some((id) => id && id !== 'undefined' && user.bid != id) }) // eslint-disable-line eqeqeq

    if (hasDuplicateKey) {
      res.status(400).json({ error: 'Duplicate ProductId, BasketId or quantity parameter' })
      return
    }
    const requestedBasketId = req.body?.BasketId
    if (!user?.bid || (requestedBasketId && requestedBasketId !== 'undefined' && Number(user.bid) !== Number(requestedBasketId))) {
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
      return
    }

    const basketItemInstance = BasketItemModel.build({
      ProductId: req.body.ProductId,
      BasketId: user.bid,
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
