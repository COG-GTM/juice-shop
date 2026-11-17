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
  customerReference: z.union([z.string(), z.array(z.string())]).optional(),
  couponCode: z.string().optional()
}).strict()

const orderLinesSchema = z.union([orderLineSchema, z.array(orderLineSchema)])

function isValidOrderLinesData (orderLinesData: unknown) {
  if (orderLinesData === undefined || orderLinesData === '') return true
  if (typeof orderLinesData !== 'string') return false
  try {
    return orderLinesSchema.safeParse(JSON.parse(orderLinesData)).success
  } catch {
    return false
  }
}

export function b2bOrder () {
  return ({ body }: Request, res: Response) => {
    if (!isValidOrderLinesData(body.orderLinesData)) {
      res.status(400).json({ error: 'Invalid orderLinesData: expected JSON order line(s)' })
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
