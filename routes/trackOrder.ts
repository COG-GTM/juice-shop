/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'
import * as security from '../lib/insecurity'

export function trackOrder () {
  return (req: Request, res: Response) => {
    const id = utils.trunc(String(req.params.id).replace(/[^\w-]+/g, ''), 60)

    // security.isAuthorized() has already verified the token's signature at this point
    const email: string | undefined = security.decode(utils.jwtFrom(req) as string)?.data?.email
    if (!email) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    // Orders are persisted with an obfuscated email address and an id prefixed by the hash of the full one
    const obfuscatedEmail = email.replace(/[aeiou]/gi, '*')
    const orderIdPrefix = security.hash(email).slice(0, 4) + '-'

    db.ordersCollection.find({ orderId: id, email: obfuscatedEmail }).then((order: any) => {
      const result = utils.queryResultToJson(order.filter((entry: any) => String(entry.orderId).startsWith(orderIdPrefix)))
      if (result.data[0] === undefined) {
        result.data[0] = { orderId: id }
      }
      res.json(result)
    }, () => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}
