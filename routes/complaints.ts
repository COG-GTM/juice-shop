/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { ComplaintModel } from '../models/complaint'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export const listComplaints = () => async (req: Request, res: Response) => {
  const user = security.decode(utils.jwtFrom(req))?.data
  if (user?.id === undefined || user?.id === null) {
    return res.status(401).json({ status: 'error', message: 'Unauthorized' })
  }
  const where = user.role === security.roles.admin ? {} : { UserId: user.id }
  const complaints = await ComplaintModel.findAll({ where, order: [['id', 'ASC']] })
  res.json({ status: 'success', data: complaints })
}
