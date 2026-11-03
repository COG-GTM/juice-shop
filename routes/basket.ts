/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'

import * as utils from '../lib/utils'
import { findOwnBasket } from '../lib/basketOwnership'

export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const basket = await findOwnBasket(req, req.params.id, { include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
      if (basket == null) {
        return res.status(403).json({ status: 'error', message: 'Access to this basket is forbidden.' })
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
