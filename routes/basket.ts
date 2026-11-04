/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'
import * as challengeUtils from '../lib/challengeUtils'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'

export function authenticatedUserIdFrom (req: Request): number | undefined {
  const user = security.authenticatedUsers.from(req)
  if (user?.data?.id !== undefined) {
    return user.data.id
  }
  const token = utils.jwtFrom(req)
  return token && security.verify(token) ? security.decode(token)?.data?.id : undefined
}

export async function isBasketOwner (req: Request, basketId: unknown) {
  const userId = authenticatedUserIdFrom(req)
  if (userId === undefined || basketId === undefined || basketId === null) {
    return false
  }
  const basket = await BasketModel.findByPk(basketId as number)
  return basket !== null && basket.UserId === userId
}

export function verifyBasketOwnership () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!(await isBasketOwner(req, req.params.id))) {
        res.status(403).json({ status: 'error', message: 'Access to this basket is forbidden' })
        return
      }
      next()
    } catch (error) {
      next(error)
    }
  }
}

export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = req.params.id
      const basket = await BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
      /* jshint eqeqeq:false */
      challengeUtils.solveIf(challenges.basketAccessChallenge, () => {
        const user = security.authenticatedUsers.from(req)
        return user && id && id !== 'undefined' && id !== 'null' && id !== 'NaN' && user.bid && user?.bid != parseInt(id, 10) // eslint-disable-line eqeqeq
      })
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
