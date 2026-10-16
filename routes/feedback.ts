/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function authorizeFeedbackDeletion () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = security.rs256VerifiedPayload(utils.jwtFrom(req))
    if (decodedToken?.data?.role === security.roles.admin) {
      next()
      return
    }
    const feedback = await FeedbackModel.findByPk(req.params.id)
    const userId = decodedToken?.data?.id
    if (feedback !== null && feedback.UserId !== null && userId !== undefined && userId !== null && String(feedback.UserId) === String(userId)) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}
