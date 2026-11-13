/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const callerOf = (req: Request) => {
  const token = utils.jwtFrom(req)
  if (!token) return undefined
  return security.authenticatedUsers.get(token)?.data ?? (security.verify(token) ? security.decode(token)?.data : undefined)
}

export function requireFeedbackOwnerOrAdmin () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const caller = callerOf(req)
    if (caller?.role === security.roles.admin) {
      next()
      return
    }
    const feedback = /^\d+$/.test(req.params.id) ? await FeedbackModel.findByPk(Number(req.params.id)) : null
    if (caller?.id != null && feedback?.UserId != null && feedback.UserId === caller.id) {
      next()
    } else {
      res.status(403).json({ status: 'error', message: 'Malicious activity detected' })
    }
  }
}
