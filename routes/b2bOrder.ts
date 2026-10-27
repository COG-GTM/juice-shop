/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'

interface OrderLine {
  productId: number
  quantity: number
  customerReference?: string | string[]
  couponCode?: string
}

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    const orderLinesData = body.orderLinesData
    if (orderLinesData !== undefined && orderLinesData !== null && orderLinesData !== '') {
      if (parseOrderLinesData(orderLinesData) === null) {
        res.status(400).json({ error: 'Invalid orderLinesData: expected a JSON order line or array of order lines' })
        return
      }
    }
    res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}

export function parseOrderLinesData (orderLinesData: unknown): OrderLine[] | null {
  if (typeof orderLinesData !== 'string') return null
  let parsed: unknown
  try {
    parsed = JSON.parse(orderLinesData)
  } catch {
    return null
  }
  const lines = Array.isArray(parsed) ? parsed : [parsed]
  return lines.length > 0 && lines.every(isValidOrderLine) ? lines : null
}

function isValidOrderLine (line: unknown): line is OrderLine {
  if (typeof line !== 'object' || line === null || Array.isArray(line)) return false
  const { productId, quantity, customerReference, couponCode } = line as Record<string, unknown>
  if (!Number.isInteger(productId) || !Number.isInteger(quantity) || (quantity as number) < 1) return false
  if (customerReference !== undefined && typeof customerReference !== 'string' &&
    !(Array.isArray(customerReference) && customerReference.every(ref => typeof ref === 'string'))) return false
  if (couponCode !== undefined && typeof couponCode !== 'string') return false
  return true
}
