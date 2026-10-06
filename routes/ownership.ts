/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { FeedbackModel } from '../models/feedback'
import { ComplaintModel } from '../models/complaint'
import * as security from '../lib/insecurity'

export function checkFeedbackDeletion () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ status: 'error', message: 'Unauthorized' })
    }
    const feedback = await FeedbackModel.findOne({ where: { id: req.params.id } })
    if (feedback == null) {
      next()
      return
    }
    if (user.data.role === security.roles.admin || (feedback.UserId != null && feedback.UserId === user.data.id)) {
      next()
    } else {
      res.status(403).json({ status: 'error', message: 'Malicious activity detected.' })
    }
  }
}

export function getComplaints () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ status: 'error', message: 'Unauthorized' })
    }
    const where = user.data.role === security.roles.admin ? {} : { UserId: user.data.id }
    const complaints = await ComplaintModel.findAll({ where })
    res.json({ status: 'success', data: complaints })
  }
}

// Hints are shared instance state that the Score Board unlocks anonymously, so the only permitted update is { unlocked: true }
export function restrictHintUpdate () {
  return (req: Request, res: Response, next: NextFunction) => {
    const keys = Object.keys(req.body ?? {})
    if (keys.length === 1 && keys[0] === 'unlocked' && req.body.unlocked === true) {
      next()
    } else {
      res.status(403).json({ status: 'error', message: 'Only unlocking a hint is allowed.' })
    }
  }
}
