/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const callerFrom = (req: Request): { id?: number, role?: string } | undefined => {
  const token = utils.jwtFrom(req)
  try {
    if (!security.verify(token)) return undefined
    const payload = security.decode(token)
    if (typeof payload?.exp === 'number' && payload.exp * 1000 <= Date.now()) return undefined
    return payload?.data
  } catch {
    return undefined
  }
}

const isAdminRequest = (req: Request) => callerFrom(req)?.role === security.roles.admin

export function deleteOwnFeedbackOnly () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const caller = callerFrom(req)
    if (caller?.role === security.roles.admin) {
      next()
      return
    }
    const feedback = typeof caller?.id === 'number' ? await FeedbackModel.findByPk(req.params.id) : null
    if (feedback !== null && feedback.UserId === caller?.id) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

const withoutAuthor = (feedback: any) => {
  const plain = { ...(typeof feedback?.toJSON === 'function' ? feedback.toJSON() : feedback) }
  delete plain.UserId
  return plain
}

export function hideFeedbackAuthors () {
  return (req: Request, res: Response, context: { instance: any, continue: any }) => {
    if (!isAdminRequest(req) && context.instance) {
      context.instance = Array.isArray(context.instance) ? context.instance.map(withoutAuthor) : withoutAuthor(context.instance)
    }
    return context.continue
  }
}
