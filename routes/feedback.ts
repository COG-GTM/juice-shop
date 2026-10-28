/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'

export function checkFeedbackDeletion () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.userFrom(req)
    const feedback = await FeedbackModel.findOne({ where: { id: req.params.id } })
    if (feedback == null) {
      res.status(404).json({ error: 'No such feedback found!' })
    } else if (user?.role === security.roles.admin || (user?.id != null && feedback.UserId === user.id)) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}
