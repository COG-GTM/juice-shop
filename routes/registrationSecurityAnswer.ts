/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { SecurityQuestionModel } from '../models/securityQuestion'
import { SecurityAnswerModel } from '../models/securityAnswer'

interface PendingSecurityAnswer {
  SecurityQuestionId: number
  answer: string
}

export function validateRegistrationSecurityAnswer () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const { securityQuestion, securityAnswer } = req.body ?? {}
    if (securityQuestion == null && securityAnswer == null) {
      next()
      return
    }
    const questionId = Number(typeof securityQuestion === 'object' ? securityQuestion?.id : securityQuestion)
    const validAnswer = typeof securityAnswer === 'string' && securityAnswer.trim() !== ''
    if (!Number.isInteger(questionId) || !validAnswer || await SecurityQuestionModel.findByPk(questionId) == null) {
      return res.status(400).json({ status: 'error', message: 'Invalid security question or answer.' })
    }
    res.locals.pendingSecurityAnswer = { SecurityQuestionId: questionId, answer: securityAnswer } satisfies PendingSecurityAnswer
    next()
  }
}

export function saveRegistrationSecurityAnswer () {
  return async (req: Request, res: Response, context: { instance: { id: number }, continue: any }) => {
    const pending: PendingSecurityAnswer | undefined = res.locals.pendingSecurityAnswer
    if (pending != null) {
      await SecurityAnswerModel.create({ UserId: context.instance.id, ...pending })
    }
    return context.continue
  }
}
