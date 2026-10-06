/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'

const MAX_ORDER_LINES_DATA_LENGTH = 100000
const MAX_ORDER_LINES = 1000

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    const orderLinesData = body.orderLinesData ?? ''
    if (orderLinesData !== '' && !isValidOrderLinesData(orderLinesData)) {
      res.status(400)
      next(new Error('Invalid orderLinesData: expected a JSON order line or array of order lines'))
      return
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

function isValidOrderLinesData (data: unknown) {
  if (typeof data !== 'string' || data.length > MAX_ORDER_LINES_DATA_LENGTH) {
    return false
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(data)
  } catch {
    return false
  }
  const orderLines = Array.isArray(parsed) ? parsed : [parsed]
  return orderLines.length > 0 && orderLines.length <= MAX_ORDER_LINES && orderLines.every(isValidOrderLine)
}

function isValidOrderLine (orderLine: unknown) {
  if (typeof orderLine !== 'object' || orderLine === null || Array.isArray(orderLine)) {
    return false
  }
  const { productId, quantity, customerReference, couponCode } = orderLine as Record<string, unknown>
  return Number.isSafeInteger(productId) &&
    Number.isSafeInteger(quantity) && (quantity as number) >= 1 &&
    (customerReference === undefined || typeof customerReference === 'string' ||
      (Array.isArray(customerReference) && customerReference.every(reference => typeof reference === 'string'))) &&
    (couponCode === undefined || typeof couponCode === 'string')
}
