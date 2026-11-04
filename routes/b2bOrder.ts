/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'

const MAX_ORDER_LINES_DATA_LENGTH = 100000

export function b2bOrder () {
  return ({ body }: Request, res: Response) => {
    const orderLinesData = body?.orderLinesData
    if (orderLinesData !== undefined && orderLinesData !== null && orderLinesData !== '' && !isValidOrderLinesData(orderLinesData)) {
      res.status(400).json({ error: 'Invalid orderLinesData: expected a JSON array of order lines with integer productId and positive integer quantity.' })
      return
    }
    res.json({ cid: body?.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
  }

  function isValidOrderLinesData (orderLinesData: unknown) {
    if (typeof orderLinesData !== 'string' || orderLinesData.length > MAX_ORDER_LINES_DATA_LENGTH) {
      return false
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(orderLinesData)
    } catch {
      return false
    }
    const orderLines = Array.isArray(parsed) ? parsed : [parsed]
    return orderLines.length > 0 && orderLines.every(isValidOrderLine)
  }

  function isValidOrderLine (orderLine: unknown) {
    if (typeof orderLine !== 'object' || orderLine === null || Array.isArray(orderLine)) {
      return false
    }
    const { productId, quantity } = orderLine as Record<string, unknown>
    return Number.isInteger(productId) && Number.isInteger(quantity) && (quantity as number) >= 1
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
