/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'

export function checkFeedbackDeletionAllowed () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)?.data
    if (user == null) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    const isAdmin = user.role === security.roles.admin
    const ownsFeedback = await FeedbackModel.count({ where: { id: req.params.id, UserId: user.id } }) > 0
    if (isAdmin || ownsFeedback) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}
