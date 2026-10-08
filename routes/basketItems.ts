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

const singleValuedKeys = ['ProductId', 'BasketId', 'quantity']

function hasDuplicateKeys (rawBody: string | undefined) {
  if (!rawBody) {
    return false
  }
  const seen = new Set<string>()
  for (const { key } of utils.parseJsonCustom(rawBody)) {
    if (singleValuedKeys.includes(key)) {
      if (seen.has(key)) {
        return true
      }
      seen.add(key)
    }
  }
  return false
}

function isValidQuantity (quantity: unknown): quantity is number {
  return typeof quantity === 'number' && Number.isSafeInteger(quantity) && quantity >= 1
}

function sessionBasketId (req: Request) {
  const user = security.authenticatedUsers.from(req)
  return user?.bid != null ? Number(user.bid) : undefined
}

export function addBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const bid = sessionBasketId(req)
    if (bid === undefined) {
      res.status(401).json({ error: 'Invalid BasketId' })
      return
    }
    if (req.body.BasketId !== undefined && Number(req.body.BasketId) !== bid) {
      res.status(401).json({ error: 'Invalid BasketId' })
      return
    }
    const basketItemInstance = BasketItemModel.build({
      ProductId: req.body.ProductId,
      BasketId: bid,
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
    try {
      if (hasDuplicateKeys((req as RequestWithRawBody).rawBody)) {
        res.status(400).json({ error: 'Duplicate keys in request body' })
        return
      }
    } catch (error) {
      res.status(400).json({ error: 'Malformed request body' })
      return
    }
    if (!isValidQuantity(req.body.quantity)) {
      res.status(400).json({ error: 'Quantity must be a positive integer' })
      return
    }
    void quantityCheck(req, res, next, req.body.ProductId, req.body.quantity).catch((error: Error) => {
      next(error)
    })
  }
}

async function findOwnedBasketItem (req: Request, res: Response) {
  const bid = sessionBasketId(req)
  if (bid === undefined) {
    res.status(401).json({ error: 'Invalid BasketId' })
    return undefined
  }
  const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
  if (item == null) {
    res.status(404).json({ error: 'No such item found!' })
    return undefined
  }
  if (item.BasketId == null || Number(item.BasketId) !== bid) {
    res.status(403).json({ error: 'Not allowed to modify this basket item' })
    return undefined
  }
  return item
}

export function ownershipCheckBeforeBasketItemDeletion () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await findOwnedBasketItem(req, res)
      if (item !== undefined) {
        next()
      }
    } catch (error) {
      next(error)
    }
  }
}

export function quantityCheckBeforeBasketItemUpdate () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await findOwnedBasketItem(req, res)
      if (item === undefined) {
        return
      }
      if (req.body.quantity !== undefined) {
        if (!isValidQuantity(req.body.quantity)) {
          res.status(400).json({ error: 'Quantity must be a positive integer' })
          return
        }
        await quantityCheck(req, res, next, item.ProductId, req.body.quantity)
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
