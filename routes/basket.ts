/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

export async function authenticatedBasketId (req: Request): Promise<number | undefined> {
  const user = security.authenticatedUsers.from(req)
  if (user?.bid != null) {
    return user.bid
  }
  if (user?.data?.id == null) {
    return undefined
  }
  const basket = await BasketModel.findOne({ where: { UserId: user.data.id } })
  return basket?.id
}

export async function ownedBasketId (req: Request, requestedId: unknown): Promise<number | undefined> {
  const bid = await authenticatedBasketId(req)
  return bid != null && String(requestedId) === String(bid) ? bid : undefined
}

export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = await ownedBasketId(req, req.params.id)
      if (id == null) {
        return res.status(403).json({ error: 'Basket does not belong to the authenticated user.' })
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
