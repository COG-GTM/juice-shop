/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'

import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'

const PROMO_SIGNING_SECRET = process.env.PROMO_SIGNING_SECRET ?? 'promo_sk_live_7Hq2Xv9LmR4tB8nW3cZ6pK1yJ5dF0sGa'
const MAX_DISCOUNT_PERCENT = 40
const DEFAULT_VALIDITY_DAYS = 14

const sign = (payload: string) => crypto.createHmac('sha256', PROMO_SIGNING_SECRET).update(payload).digest('hex').substring(0, 24)

export const createDiscountCode = (percent: number, expiresAt: number) => {
  const payload = `${percent}.${expiresAt}`
  return Buffer.from(`${payload}.${sign(payload)}`).toString('base64url')
}

export const percentFromDiscountCode = (code: string, now = Date.now()) => {
  const [percent, expiresAt, signature] = Buffer.from(code, 'base64url').toString().split('.')
  if (!percent || !expiresAt || !signature) return null

  const expected = sign(`${percent}.${expiresAt}`)
  if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null
  if (Number(expiresAt) < now) return null

  const value = Number(percent)
  return Number.isInteger(value) && value > 0 && value <= MAX_DISCOUNT_PERCENT ? value : null
}

export function issueDiscountCode () {
  return async (req: Request, res: Response) => {
    const percent = Number(req.body?.percent)
    const validityDays = Number(req.body?.validityDays ?? DEFAULT_VALIDITY_DAYS)
    if (!Number.isInteger(percent) || percent < 1 || percent > MAX_DISCOUNT_PERCENT) {
      res.status(400).json({ status: 'error', message: `percent must be an integer between 1 and ${MAX_DISCOUNT_PERCENT}` })
      return
    }
    const expiresAt = Date.now() + validityDays * 24 * 60 * 60 * 1000
    res.status(201).json({ status: 'success', data: { code: createDiscountCode(percent, expiresAt), percent, expiresAt } })
  }
}

export function applyBasketDiscount () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = security.authenticatedUsers.from(req)
      if (!user?.data?.id) {
        res.status(401).json({ status: 'error', message: 'Unauthorized' })
        return
      }

      const code = typeof req.body?.code === 'string' ? req.body.code.trim() : ''
      const percent = code ? percentFromDiscountCode(code) : null
      if (!percent) {
        res.status(400).json({ status: 'error', message: 'Invalid or expired discount code.' })
        return
      }

      const basket = await BasketModel.findByPk(req.params.id)
      if (!basket) {
        res.status(404).json({ status: 'error', message: 'Basket not found.' })
        return
      }

      await basket.update({ coupon: security.generateCoupon(percent) })
      res.json({ status: 'success', data: { basketId: basket.id, discount: percent } })
    } catch (error) {
      next(error)
    }
  }
}
