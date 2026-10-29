/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

async function userIdOf (req: Request): Promise<number | undefined> {
  const user = security.authenticatedUsers.from(req)
  if (user?.data?.id != null) {
    return user.data.id
  }
  const token = utils.jwtFrom(req)
  if (token == null) {
    return undefined
  }
  return await new Promise<number | undefined>((resolve) => {
    jwt.verify(token, security.publicKey, (err: Error | null, decoded: any) => {
      resolve(err === null ? decoded?.data?.id : undefined)
    })
  })
}

export async function basketIdOf (req: Request): Promise<number | undefined> {
  const userId = await userIdOf(req)
  if (userId == null) {
    return undefined
  }
  const basket = await BasketModel.findOne({ where: { UserId: userId } })
  return basket?.id
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
