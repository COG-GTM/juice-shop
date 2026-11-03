/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'

export function ensureFeedbackOwnershipOrAdmin () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const feedback = await FeedbackModel.findOne({ where: { id: req.params.id } })
    const user = security.userFromToken(req)
    if (feedback == null || user?.role === security.roles.admin || (feedback.UserId != null && feedback.UserId === user?.id)) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}
