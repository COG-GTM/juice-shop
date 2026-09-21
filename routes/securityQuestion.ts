/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import { SecurityQuestionModel } from '../models/securityQuestion'
import * as security from '../lib/insecurity'

// Keeps the response shape identical for unknown accounts so the endpoint cannot be used to enumerate registered emails
async function decoyQuestionFor (email: string) {
  const questions = await SecurityQuestionModel.findAll({ order: [['id', 'ASC']] })
  if (questions.length === 0) {
    return null
  }
  const index = parseInt(security.hmac(`security-question-decoy:${email.toLowerCase()}`).slice(0, 8), 16) % questions.length
  return questions[index]
}

export function securityQuestion () {
  return async ({ query }: Request, res: Response, next: NextFunction) => {
    const email = query.email
    try {
      const answer = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email: email?.toString() }
        }]
      })
      const question = answer != null
        ? await SecurityQuestionModel.findByPk(answer.SecurityQuestionId)
        : await decoyQuestionFor(email?.toString() ?? '')
      res.json({ question })
    } catch (error) {
      next(error)
    }
  }
}
