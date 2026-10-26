/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'

interface OrderLine {
  productId: number
  quantity: number
  [key: string]: unknown
}

export function b2bOrder () {
  return ({ body }: Request, res: Response) => {
    if (body.orderLinesData !== undefined && parseOrderLinesData(body.orderLinesData) === null) {
      return res.status(400).json({ error: 'Invalid orderLinesData: expected a JSON order line or array of order lines with integer productId and positive integer quantity' })
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

function parseOrderLinesData (orderLinesData: unknown): OrderLine[] | null {
  if (typeof orderLinesData !== 'string') return null
  let parsed: unknown
  try {
    parsed = JSON.parse(orderLinesData)
  } catch {
    return null
  }
  const lines = Array.isArray(parsed) ? parsed : [parsed]
  if (lines.length === 0 || !lines.every(isOrderLine)) return null
  return lines
}

function isOrderLine (line: unknown): line is OrderLine {
  if (typeof line !== 'object' || line === null || Array.isArray(line)) return false
  const { productId, quantity } = line as Record<string, unknown>
  return Number.isInteger(productId) && Number.isInteger(quantity) && (quantity as number) >= 1
}
