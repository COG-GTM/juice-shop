/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'

export function b2bOrder () {
  return ({ body }: Request, res: Response) => {
    const orderLinesData = body.orderLinesData
    if (orderLinesData !== undefined && orderLinesData !== null && orderLinesData !== '') {
      if (typeof orderLinesData !== 'string' || !isValidOrderLinesData(orderLinesData)) {
        res.status(400).json({ error: 'Invalid orderLinesData' })
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

function isValidOrderLinesData (orderLinesData: string) {
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
  if (typeof orderLine !== 'object' || orderLine === null || Array.isArray(orderLine)) return false
  const { productId, quantity, customerReference, couponCode } = orderLine as Record<string, unknown>
  return Number.isInteger(productId) &&
    Number.isInteger(quantity) && (quantity as number) >= 1 &&
    (customerReference === undefined || typeof customerReference === 'string' ||
      (Array.isArray(customerReference) && customerReference.every(ref => typeof ref === 'string'))) &&
    (couponCode === undefined || typeof couponCode === 'string')
}
