/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function checkFeedbackOwnership () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = utils.jwtFrom(req)
    const user = token && security.verify(token) ? security.decode(token)?.data : undefined
    const feedback = await FeedbackModel.findByPk(req.params.id)
    if (feedback == null) {
      res.status(404).json({ error: 'No such feedback found!' })
    } else if (user?.role === security.roles.admin || (user?.id != null && feedback.UserId === user.id)) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}
