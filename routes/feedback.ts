/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'

export function isFeedbackOwnerOrAdmin () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (security.isAdmin(req)) {
      next()
      return
    }
    const userId = security.authenticatedUsers.from(req)?.data?.id
    const feedback = await FeedbackModel.findByPk(req.params.id)
    if (feedback?.UserId != null && userId !== undefined && feedback.UserId === userId) {
      next()
    } else {
      res.status(403).json({ status: 'error', message: 'Malicious activity detected' })
    }
  }
}
