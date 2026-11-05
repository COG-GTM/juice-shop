/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { ComplaintModel } from '../models/complaint'
import * as security from '../lib/insecurity'

export function getComplaints () {
  return async (req: Request, res: Response) => {
    if (security.isAdmin(req)) {
      res.status(200).json({ status: 'success', data: await ComplaintModel.findAll() })
      return
    }
    const userId = security.authenticatedUsers.from(req)?.data?.id
    if (userId === undefined) {
      res.status(401).json({ status: 'error', message: 'Unknown user' })
      return
    }
    const complaints = await ComplaintModel.findAll({ where: { UserId: userId } })
    res.status(200).json({ status: 'success', data: complaints })
  }
}
