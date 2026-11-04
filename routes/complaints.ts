/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'
import { ComplaintModel } from '../models/complaint'
import * as security from '../lib/insecurity'

const callerFrom = (req: Request) => {
  const user = security.verifiedAdminOrUserClaims(req)
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
  const owner = user.role === security.roles.admin ? {} : { UserId: user.id }
  const filters = Object.fromEntries(['id', 'UserId', 'message', 'file']
    .filter(key => typeof req.query[key] === 'string')
    .map(key => [key, req.query[key]]))
  const complaints = await ComplaintModel.findAll({ where: { [Op.and]: [owner, filters] }, order: [['id', 'ASC']] })
  res.json({ status: 'success', data: complaints })
}
