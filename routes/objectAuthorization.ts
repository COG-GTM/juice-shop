/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'

function forbidden (res: Response) {
  res.status(403).json({ error: 'Malicious activity detected' })
}

export function checkUserAccess () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.verifiedTokenPayload(req)?.data
    if (user != null && (user.role === security.roles.admin || String(user.id) === req.params.id)) {
      next()
    } else {
      forbidden(res)
    }
  }
}

export function checkFeedbackAccess () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const feedback = await FeedbackModel.findOne({ where: { id: req.params.id } })
    if (feedback == null) {
      next()
      return
    }
    const user = security.verifiedTokenPayload(req)?.data
    if (user != null && (user.role === security.roles.admin || (feedback.UserId != null && feedback.UserId === user.id))) {
      next()
    } else {
      forbidden(res)
    }
  }
}

// The Score Board unlocks hints anonymously, so unlocking is the only update allowed
export function restrictHintUpdate () {
  return (req: Request, res: Response, next: NextFunction) => {
    const keys = Object.keys(req.body ?? {})
    if (keys.length === 1 && req.body.unlocked === true) {
      next()
    } else {
      forbidden(res)
    }
  }
}
