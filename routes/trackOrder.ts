/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'

// Order ids are generated as <first 4 hex chars of md5(email)>-<16 random hex chars>
const ORDER_ID_PATTERN = /^[0-9a-f]{4}-[0-9a-f]{16}$/

export function trackOrder () {
  return (req: Request, res: Response) => {
    const id = String(req.params.id)

    if (!ORDER_ID_PATTERN.test(id)) {
      res.status(400).json({ error: 'Invalid order id' })
      return
    }

    db.ordersCollection.find({ orderId: id }).then((order: any) => {
      const result = utils.queryResultToJson(order)
      if (result.data[0] === undefined) {
        result.data[0] = { orderId: id }
      }
      res.json(result)
    }, () => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}
