/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { z } from 'zod'

import * as security from '../lib/insecurity'

const orderLineSchema = z.object({
  productId: z.number().int(),
  quantity: z.number().int().min(1),
  customerReference: z.union([z.string(), z.array(z.string())]).optional()
}).passthrough()

const orderLinesDataSchema = z.union([orderLineSchema, z.array(orderLineSchema).nonempty()])

export function b2bOrder () {
  return ({ body }: Request, res: Response) => {
    const orderLinesData = body.orderLinesData
    if (orderLinesData !== undefined && orderLinesData !== '' && !isValidOrderLinesData(orderLinesData)) {
      res.status(400).json({ error: 'orderLinesData must be a JSON order line or array of order lines with integer productId and positive integer quantity' })
      return
    }
    res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
  }

  function isValidOrderLinesData (orderLinesData: unknown) {
    if (typeof orderLinesData !== 'string') return false
    try {
      return orderLinesDataSchema.safeParse(JSON.parse(orderLinesData)).success
    } catch {
      return false
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
