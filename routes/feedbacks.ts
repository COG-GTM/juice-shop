/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'

export function ensureFeedbackDeletionAllowed () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.loggedInUserFrom(req)
    if (!user?.id) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }
    if (user.role === security.roles.admin) {
      next()
      return
    }
    const feedback = await FeedbackModel.findOne({ where: { id: req.params.id, UserId: user.id } })
    if (feedback == null) {
      res.status(403).json({ status: 'error', message: 'Forbidden' })
      return
    }
    next()
  }
}
