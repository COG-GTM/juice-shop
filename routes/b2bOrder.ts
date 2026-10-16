/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'

const MAX_ORDER_LINES_DATA_LENGTH = 100000

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    const orderLinesData = body.orderLinesData ?? ''
    if (orderLinesData !== '' && !isValidOrderLinesData(orderLinesData)) {
      res.status(400)
      next(new Error('Invalid orderLinesData: expected a JSON string'))
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
  try {
    JSON.parse(data)
    return true
  } catch {
    return false
  }
}
