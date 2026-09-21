/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { createHmac, randomBytes } from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import { SecurityQuestionModel } from '../models/securityQuestion'

// Set SECURITY_QUESTION_DECOY_KEY to keep decoys consistent across replicas of a multi-instance deployment
const decoyKey = process.env.SECURITY_QUESTION_DECOY_KEY ?? randomBytes(32).toString('hex')

// Keeps the response shape identical for unknown accounts so the endpoint cannot be used to enumerate registered emails
async function decoyQuestionFor (email: string) {
  const questions = await SecurityQuestionModel.findAll({ order: [['id', 'ASC']] })
  if (questions.length === 0) {
    return null
  }
  const digest = createHmac('sha256', decoyKey).update(email.toLowerCase()).digest('hex')
  return questions[parseInt(digest.slice(0, 8), 16) % questions.length]
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
