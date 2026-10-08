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

function loggedInUserId (req: Request): number | undefined {
  const cached = security.authenticatedUsers.from(req)?.data?.id
  if (cached !== undefined) return cached
  const token = utils.jwtFrom(req)
  return security.verify(token) ? security.decode(token)?.data?.id : undefined
}

export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = req.params.id
      const user = security.authenticatedUsers.from(req)
      const userId = loggedInUserId(req)
      if (userId === undefined) {
        res.status(401).json({ status: 'error', message: 'Unauthorized' })
        return
      }
      /* jshint eqeqeq:false */
      challengeUtils.solveIf(challenges.basketAccessChallenge, () => {
        return user && id && id !== 'undefined' && id !== 'null' && id !== 'NaN' && user.bid && user?.bid != parseInt(id, 10) // eslint-disable-line eqeqeq
      })
      const basket = await BasketModel.findOne({ where: { id, UserId: userId }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
      if (basket == null) {
        res.status(403).json({ status: 'error', message: 'Not allowed' })
        return
      }
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
