/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'

const MAX_ORDER_LINES_DATA_LENGTH = 100000
const MAX_ORDER_LINES = 1000
const ORDER_LINE_KEYS = new Set(['productId', 'quantity', 'customerReference', 'couponCode'])

export function b2bOrder () {
  return ({ body }: Request, res: Response) => {
    const orderLinesData = body?.orderLinesData
    if (orderLinesData !== undefined && orderLinesData !== null && orderLinesData !== '' && !isValidOrderLinesData(orderLinesData)) {
      res.status(400).json({ error: 'Invalid orderLinesData: expected a JSON string with one or more order lines ({ productId, quantity, customerReference?, couponCode? }).' })
      return
    }
    res.json({ cid: body?.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}

export function isValidOrderLinesData (orderLinesData: unknown): boolean {
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
  return orderLines.length > 0 && orderLines.length <= MAX_ORDER_LINES && orderLines.every(isValidOrderLine)
}

function isValidOrderLine (line: unknown): boolean {
  if (line === null || typeof line !== 'object' || Array.isArray(line)) {
    return false
  }
  const { productId, quantity, customerReference, couponCode } = line as Record<string, unknown>
  return Object.keys(line).every(key => ORDER_LINE_KEYS.has(key)) &&
    isPositiveSafeInteger(productId) &&
    isPositiveSafeInteger(quantity) &&
    (customerReference === undefined || typeof customerReference === 'string' || (Array.isArray(customerReference) && customerReference.every(ref => typeof ref === 'string'))) &&
    (couponCode === undefined || typeof couponCode === 'string')
}

function isPositiveSafeInteger (value: unknown): boolean {
  return Number.isSafeInteger(value) && (value as number) >= 1
}
