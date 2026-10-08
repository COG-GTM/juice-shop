/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import clarinet from 'clarinet'
import { BasketModel } from '../models/basket'
import { BasketItemModel } from '../models/basketitem'
import { QuantityModel } from '../models/quantity'
import * as challengeUtils from '../lib/challengeUtils'

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

function countTopLevelBasketItemKeys (json: string) {
  const parser = clarinet.parser()
  const counts: Record<string, number> = {}
  let depth = 0
  const countKey = (key?: string) => {
    if (depth === 1 && key !== undefined && (basketItemKeys as readonly string[]).includes(key)) {
      counts[key] = (counts[key] ?? 0) + 1
    }
  }
  parser.onopenobject = (key?: string) => {
    depth++
    countKey(key)
  }
  parser.onkey = countKey
  parser.oncloseobject = () => { depth-- }
  parser.onopenarray = () => { depth++ }
  parser.onclosearray = () => { depth-- }
  parser.onerror = (error: Error) => { throw error }
  parser.write(json).close()
  return counts
}

function parseBasketItemBody (req: Request): { fields: BasketItemFields, duplicateKeys: boolean } {
  const rawBody = (req as RequestWithRawBody).rawBody
  const json = typeof rawBody === 'string' ? rawBody : JSON.stringify(req.body ?? {})
  const duplicateKeys = Object.values(countTopLevelBasketItemKeys(json)).some(count => count > 1)
  const body = JSON.parse(json)
  const fields: BasketItemFields = {}
  if (body !== null && typeof body === 'object' && !Array.isArray(body)) {
    for (const key of basketItemKeys) {
      if (Object.prototype.hasOwnProperty.call(body, key)) {
        fields[key] = body[key]
      }
    }
  }
  return { fields, duplicateKeys }
}

async function sessionBasketId (user: { bid?: number, data?: { id?: number } } | undefined) {
  if (user?.bid != null) {
    return user.bid
  }
  if (user?.data?.id == null) {
    return undefined
  }
  const basket = await BasketModel.findOne({ where: { UserId: user.data.id } })
  return basket?.id
}

function hasForeignBasketId (basketId: any, userBid: any) {
  return basketId != null && basketId !== 'undefined' && Number(basketId) !== Number(userBid)
}

export function addBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { fields, duplicateKeys } = parseBasketItemBody(req)
      if (duplicateKeys) {
        res.status(400).json({ status: 'error', message: 'Duplicate keys are not allowed' })
        return
      }
      const bid = await sessionBasketId(security.authenticatedUsers.from(req))
      if (bid == null || hasForeignBasketId(fields.BasketId, bid)) {
        res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
        return
      }
      const addedBasketItem = await BasketItemModel.build({
        ProductId: fields.ProductId,
        BasketId: bid,
        quantity: fields.quantity
      }).save()
      res.json({ status: 'success', data: addedBasketItem })
    } catch (error) {
      next(error)
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
