/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ComplaintModel } from '../models/complaint'
import * as security from '../lib/insecurity'

export function getComplaints () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = security.authenticatedUsers.from(req)?.data?.id
      const complaints = userId === undefined || userId === null ? [] : await ComplaintModel.findAll({ where: { UserId: userId } })
      res.json({ status: 'success', data: complaints })
    } catch (error) {
      next(error)
    }
  }
}
