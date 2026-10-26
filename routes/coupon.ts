/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'

export function applyCoupon () {
  return async ({ params, body }: Request, res: Response, next: NextFunction) => {
    try {
      const id = params.id
      const UserId = body?.UserId
      if (UserId == null) {
        return res.status(401).json({ status: 'error', message: 'Unauthorized' })
      }
      const basket = await BasketModel.findOne({ where: { id, UserId } })
      if (!basket) {
        return res.status(403).json({ status: 'error', message: 'Not allowed' })
      }

      let coupon: string | undefined | null = params.coupon ? decodeURIComponent(params.coupon) : undefined
      const discount = security.discountFromCoupon(coupon)
      coupon = discount ? coupon : null

      await basket.update({ coupon: coupon?.toString() })
      if (discount) {
        return res.json({ discount })
      } else {
        return res.status(404).send('Invalid coupon.')
      }
    } catch (error) {
      next(error)
    }
  }
}
