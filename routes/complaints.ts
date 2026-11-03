/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { ComplaintModel } from '../models/complaint'
import * as security from '../lib/insecurity'

export function getComplaints () {
  return async (req: Request, res: Response) => {
    const user = security.userFromToken(req)
    if (user?.id === undefined) {
      res.status(401).json({ status: 'error', data: 'Unauthorized' })
      return
    }
    const complaints = user.role === security.roles.admin
      ? await ComplaintModel.findAll()
      : await ComplaintModel.findAll({ where: { UserId: user.id } })
    res.json({ status: 'success', data: complaints })
  }
}
