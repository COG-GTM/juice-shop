/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import { SecurityQuestionModel } from '../models/securityQuestion'
import * as security from '../lib/insecurity'

async function decoyQuestionFor (email: string) {
  const questions = await SecurityQuestionModel.findAll({ order: [['id', 'ASC']] })
  if (questions.length === 0) {
    return null
  }
  const index = parseInt(security.hmac(email.toLowerCase()).substring(0, 8), 16) % questions.length
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
        : await decoyQuestionFor(String(email))
      res.json({ question })
    } catch (error) {
      next(error)
    }
  }
}
