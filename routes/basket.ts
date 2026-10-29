/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

export async function basketIdOf (req: Request): Promise<number | undefined> {
  const user = security.authenticatedUsers.from(req)
  if (user?.bid != null) {
    return user.bid
  }
  if (user?.data?.id != null) {
    const basket = await BasketModel.findOne({ where: { UserId: user.data.id } })
    return basket?.id
  }
  return undefined
}

export async function ownsBasket (req: Request, basketId: unknown): Promise<boolean> {
  const bid = await basketIdOf(req)
  return bid != null && basketId != null && String(bid) === String(basketId)
}

export function ensureBasketOwnership () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (await ownsBasket(req, req.params.id)) {
      next()
    } else {
      res.status(403).json({ status: 'error', message: 'Access to this basket is not allowed' })
    }
  }
}

export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = req.params.id
      if (!await ownsBasket(req, id)) {
        res.status(403).json({ status: 'error', message: 'Access to this basket is not allowed' })
        return
      }
      const basket = await BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
      if (((basket?.Products) != null) && basket.Products.length > 0) {
        for (let i = 0; i < basket.Products.length; i++) {
          basket.Products[i].name = req.__(basket.Products[i].name)
        }
      }

      res.json(utils.queryResultToJson(basket))
    } catch (error) {
      next(error)
    }
  }
}
