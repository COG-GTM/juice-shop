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

interface BasketItemFields {
  ProductId?: any
  BasketId?: any
  quantity?: any
}

const basketItemKeys = ['ProductId', 'BasketId', 'quantity'] as const

function parseBasketItemBody (req: Request): { fields: BasketItemFields, duplicateKeys: boolean } {
  const rawBody = (req as RequestWithRawBody).rawBody
  const fields: BasketItemFields = {}
  let duplicateKeys = false
  for (const { key, value } of utils.parseJsonCustom(typeof rawBody === 'string' ? rawBody : JSON.stringify(req.body ?? {}))) {
    if ((basketItemKeys as readonly string[]).includes(key)) {
      if (Object.prototype.hasOwnProperty.call(fields, key)) {
        duplicateKeys = true
      }
      fields[key as keyof BasketItemFields] = value
    }
  }
  return { fields, duplicateKeys }
}

function hasForeignBasketId (basketId: any, userBid: any) {
  return basketId != null && basketId !== 'undefined' && Number(basketId) !== Number(userBid)
}

export function addBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const { fields, duplicateKeys } = parseBasketItemBody(req)
    const user = security.authenticatedUsers.from(req)
    if (duplicateKeys) {
      res.status(400).json({ status: 'error', message: 'Duplicate keys are not allowed' })
    } else if (user?.bid == null || hasForeignBasketId(fields.BasketId, user.bid)) {
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
    } else {
      const basketItem = {
        ProductId: fields.ProductId,
        BasketId: user.bid,
        quantity: fields.quantity
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
    let parsed
    try {
      parsed = parseBasketItemBody(req)
    } catch (error) {
      next(error)
      return
    }
    if (parsed.duplicateKeys) {
      res.status(400).json({ status: 'error', message: 'Duplicate keys are not allowed' })
      return
    }
    void quantityCheck(req, res, next, parsed.fields.ProductId, parsed.fields.quantity).catch((error: Error) => {
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
