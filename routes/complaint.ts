/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ComplaintModel } from '../models/complaint'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function bindComplaintToCurrentUser () {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = utils.jwtFrom(req)
    const user = security.authenticatedUsers.from(req)
    const userId = user?.data?.id ?? (token ? security.decode(token)?.data?.id : undefined)
    req.body = { ...req.body, UserId: userId ?? null }
    next()
  }
}

export function getOwnComplaints () {
  return async (req: Request, res: Response) => {
    const complaints = req.body.UserId ? await ComplaintModel.findAll({ where: { UserId: req.body.UserId } }) : []
    res.status(200).json({ status: 'success', data: complaints })
  }
}
