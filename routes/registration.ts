/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import type { NextFunction, Request, Response } from 'express'

import * as security from '../lib/insecurity'
import { SecurityQuestionModel } from '../models/securityQuestion'

export const restrictRegistrationAttributes = () => async (req: Request, res: Response, next: NextFunction) => {
  if (res.headersSent) return

  try {
    const { email, password, passwordRepeat, securityQuestion, securityAnswer } = req.body ?? {}
    const securityQuestionId = securityQuestion?.id

    if (securityQuestionId !== undefined || securityAnswer !== undefined) {
      const questionId = Number(securityQuestionId)
      if (!Number.isInteger(questionId) || typeof securityAnswer !== 'string' || securityAnswer.length === 0 || !await SecurityQuestionModel.findByPk(questionId)) {
        res.status(400).json({ status: 'error', message: 'Invalid security question or answer' })
        return
      }
      res.locals.securityAnswer = { SecurityQuestionId: questionId, answer: securityAnswer }
    }

    req.body = { email, password, passwordRepeat, role: security.roles.customer }
    next()
  } catch (err) {
    next(err)
  }
}
