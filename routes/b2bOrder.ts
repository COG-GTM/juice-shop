/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'

interface OrderLine {
  productId: number
  quantity: number
}

export function b2bOrder () {
  return ({ body }: Request, res: Response) => {
    const orderLinesData = body.orderLinesData
    if (orderLinesData !== undefined && orderLinesData !== null && orderLinesData !== '' && parseOrderLines(orderLinesData) === null) {
      res.status(400).json({ status: 'error', error: 'Invalid orderLinesData' })
      return
    }
    res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
  }

  function parseOrderLines (orderLinesData: unknown): OrderLine[] | null {
    if (typeof orderLinesData !== 'string') return null
    let parsed: unknown
    try {
      parsed = JSON.parse(orderLinesData)
    } catch {
      return null
    }
    const orderLines: unknown[] = Array.isArray(parsed) ? parsed : [parsed]
    return orderLines.length > 0 && orderLines.every(isOrderLine) ? orderLines : null
  }

  function isOrderLine (line: unknown): line is OrderLine {
    if (typeof line !== 'object' || line === null || Array.isArray(line)) return false
    const { productId, quantity } = line as Record<string, unknown>
    return Number.isInteger(productId) && Number.isInteger(quantity) && (quantity as number) >= 1
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
