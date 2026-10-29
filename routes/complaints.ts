/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ComplaintModel } from '../models/complaint'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const callerFrom = (req: Request) => {
  const user = security.decode(utils.jwtFrom(req))?.data
  return user?.id === undefined || user?.id === null ? undefined : user
}

export const setComplaintOwner = () => (req: Request, res: Response, next: NextFunction) => {
  const user = callerFrom(req)
  if (user === undefined) {
    return res.status(401).json({ status: 'error', message: 'Unauthorized' })
  }
  req.body.UserId = user.id
  next()
}

export const listComplaints = () => async (req: Request, res: Response) => {
  const user = callerFrom(req)
  if (user === undefined) {
    return res.status(401).json({ status: 'error', message: 'Unauthorized' })
  }
  const where = user.role === security.roles.admin ? {} : { UserId: user.id }
  const complaints = await ComplaintModel.findAll({ where, order: [['id', 'ASC']] })
  res.json({ status: 'success', data: complaints })
}
