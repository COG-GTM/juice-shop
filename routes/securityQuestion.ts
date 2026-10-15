/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import { SecurityQuestionModel } from '../models/securityQuestion'

const decoyKey = crypto.randomBytes(32)

// Unknown emails get a stable, unpredictable question so the response does not reveal whether an account exists
function decoyQuestionFor<T> (email: string, questions: T[]) {
  if (questions.length === 0) return null
  const digest = crypto.createHmac('sha256', decoyKey).update(email).digest()
  return questions[digest.readUInt32BE(0) % questions.length]
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
      const questions = await SecurityQuestionModel.findAll({ order: [['id', 'ASC']] })
      const question = answer != null
        ? questions.find(({ id }) => id === answer.SecurityQuestionId) ?? null
        : decoyQuestionFor(String(email), questions)
      res.json({ question })
    } catch (error) {
      next(error)
    }
  }
}
