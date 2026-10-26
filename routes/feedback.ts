/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'

export function bindFeedbackToCurrentUser () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (req.body) {
      req.body.UserId = user?.data?.id ?? null
    }
    next()
  }
}

export function ensureFeedbackDeletionAllowed () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (user?.data?.role === security.roles.admin) {
      next()
      return
    }
    const feedback = await FeedbackModel.findOne({ where: { id: req.params.id } })
    if (user?.data?.id && feedback?.UserId && feedback.UserId === user.data.id) {
      next()
    } else {
      res.status(403).json({ status: 'error', message: 'Malicious activity detected.' })
    }
  }
}
