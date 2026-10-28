/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ComplaintModel } from '../models/complaint'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function getComplaints () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = utils.jwtFrom(req)
    const user = security.authenticatedUsers.from(req)?.data ?? (security.verify(token) ? security.decode(token)?.data : undefined)
    if (user?.role === security.roles.admin) {
      next()
      return
    }
    const userId = user?.id
    if (userId == null) {
      res.status(403).json({ status: 'error', message: 'Forbidden' })
      return
    }
    const complaints = await ComplaintModel.findAll({ where: { UserId: userId } })
    res.status(200).json({ status: 'success', data: complaints })
  }
}
