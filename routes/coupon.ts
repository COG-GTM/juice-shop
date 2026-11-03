/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'
import { findOwnBasket } from '../lib/basketOwnership'

export function applyCoupon () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = req.params.id
      let coupon: string | undefined | null = req.params.coupon ? decodeURIComponent(req.params.coupon) : undefined
      const discount = security.discountFromCoupon(coupon)
      coupon = discount ? coupon : null

      const basket = await findOwnBasket(req, id)
      if (!basket) {
        return res.status(403).json({ status: 'error', message: 'Access to this basket is forbidden.' })
      }

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
