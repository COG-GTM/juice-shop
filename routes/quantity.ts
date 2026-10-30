/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { QuantityModel } from '../models/quantity'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

// The storefront only distinguishes "sold out" and "only 1-5 left", so exact stock above that stays with accounting
export const PUBLIC_QUANTITY_CAP = 6

export function getPublicQuantities () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = utils.jwtFrom(req)
    const decodedToken = token && security.verify(token) ? security.decode(token) : undefined
    if (decodedToken?.data?.role === security.roles.accounting) {
      next()
      return
    }
    const quantities = await QuantityModel.findAll({ attributes: ['ProductId', 'quantity'] })
    res.status(200).json({
      status: 'success',
      data: quantities.map(({ ProductId, quantity }) => ({ ProductId, quantity: Math.min(quantity, PUBLIC_QUANTITY_CAP) }))
    })
  }
}
