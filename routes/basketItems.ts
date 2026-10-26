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

const singleValueKeys = ['ProductId', 'BasketId', 'quantity']

function inspectBasketItemBody (req: Request) {
  const body = req.body
  let entries: Array<{ key: string, value: unknown }> = []
  try {
    entries = utils.parseJsonCustom((req as RequestWithRawBody).rawBody)
  } catch {
    return { ambiguous: true, basketIds: [] }
  }
  const basketIds = entries.filter((entry) => entry.key === 'BasketId').map((entry) => entry.value)
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return { ambiguous: true, basketIds }
  }
  const ambiguous = singleValueKeys.some((key) => {
    const occurrences = entries.filter((entry) => entry.key === key).length
    return occurrences > (Object.prototype.hasOwnProperty.call(body, key) ? 1 : 0)
  })
  return { ambiguous, basketIds }
}

async function sessionBasketId (user: ReturnType<typeof security.authenticatedUsers.from>) {
  if (!user) {
    return undefined
  }
  if (user.bid) {
    return Number(user.bid)
  }
  if (!user.data?.id) {
    return undefined
  }
  const basket = await BasketModel.findOne({ where: { UserId: user.data.id } })
  if (basket == null) {
    return undefined
  }
  user.bid = basket.id
  return basket.id
}

function sendAmbiguousBodyError (res: Response) {
  res.status(400).json({ error: 'ProductId, BasketId and quantity must each appear at most once at the top level of the request body' })
}

export function addBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (inspectBasketItemBody(req).ambiguous) {
      sendAmbiguousBodyError(res)
      return
    }

    try {
      const bid = await sessionBasketId(security.authenticatedUsers.from(req))
      const requestedBasketId = req.body.BasketId
      if (!bid || (requestedBasketId !== undefined && requestedBasketId !== null && requestedBasketId !== 'undefined' && Number(requestedBasketId) !== bid)) {
        res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
        return
      }

      const basketItemInstance = BasketItemModel.build({
        ProductId: req.body.ProductId,
        BasketId: bid,
        quantity: req.body.quantity
      })
      const addedBasketItem = await basketItemInstance.save()
      res.json({ status: 'success', data: addedBasketItem })
    } catch (error) {
      next(error)
    }
  }
}

export function quantityCheckBeforeBasketItemAddition () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const { ambiguous, basketIds } = inspectBasketItemBody(req)
    const user = security.authenticatedUsers.from(req)
    challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user?.bid && req.body?.ProductId !== undefined && req.body?.quantity !== undefined && basketIds.length > 1 && Number(basketIds[0]) === Number(user.bid) && basketIds.slice(1).some((id) => id && id !== 'undefined' && Number(id) !== Number(user.bid)) })
    if (ambiguous) {
      sendAmbiguousBodyError(res)
      return
    }
    try {
      await quantityCheck(req, res, next, req.body.ProductId, req.body.quantity)
    } catch (error) {
      next(error)
    }
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
