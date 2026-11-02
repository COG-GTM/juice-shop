/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { FeedbackModel } from '../models/feedback'

function verifiedUserFrom (req: Request): { id?: number, role?: string } | undefined {
  const token = utils.jwtFrom(req)
  return (security.verify(token) && security.decode(token)?.data) || undefined
}

export const isAdmin = (req: Request) => verifiedUserFrom(req)?.role === security.roles.admin

export function bindFeedbackAuthor () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.body && typeof req.body === 'object') {
      req.body.UserId = verifiedUserFrom(req)?.id ?? null
    }
    next()
  }
}

export function canDeleteFeedback () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = verifiedUserFrom(req)
    if (user?.role === security.roles.admin) {
      next()
      return
    }
    const feedback = await FeedbackModel.findByPk(req.params.id)
    if (feedback !== null && user?.id !== undefined && feedback.UserId !== null && feedback.UserId === user.id) {
      next()
    } else {
      res.status(403).json({ status: 'error', message: 'Not allowed to delete this feedback' })
    }
  }
}

export function stripFeedbackAuthor (req: Request, feedback: { UserId?: number | null, dataValues?: { UserId?: number | null } }) {
  if (isAdmin(req)) return
  delete feedback.UserId
  if (feedback.dataValues) delete feedback.dataValues.UserId
}
