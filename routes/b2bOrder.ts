/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    const orderLinesData = body.orderLinesData ?? ''
    if (orderLinesData !== '' && !isValidOrderLinesData(orderLinesData)) {
      res.status(400).json({ error: 'Invalid orderLinesData: expected JSON order line(s) with integer productId and positive integer quantity' })
      return
    }
    res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
  }

  function isValidOrderLinesData (data: unknown) {
    if (typeof data !== 'string') return false
    let parsed: unknown
    try {
      parsed = JSON.parse(data)
    } catch {
      return false
    }
    const orderLines = Array.isArray(parsed) ? parsed : [parsed]
    return orderLines.length > 0 && orderLines.every(isValidOrderLine)
  }

  function isValidOrderLine (line: unknown) {
    if (typeof line !== 'object' || line === null || Array.isArray(line)) return false
    const { productId, quantity, customerReference } = line as Record<string, unknown>
    return Number.isInteger(productId) &&
      Number.isInteger(quantity) && (quantity as number) >= 1 &&
      (customerReference === undefined || typeof customerReference === 'string' ||
        (Array.isArray(customerReference) && customerReference.every(ref => typeof ref === 'string')))
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
