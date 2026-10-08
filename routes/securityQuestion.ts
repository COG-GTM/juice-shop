/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { createHmac, randomBytes } from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import { SecurityQuestionModel } from '../models/securityQuestion'

// Set SECURITY_QUESTION_DECOY_KEY so all instances of a multi-node deployment return the same decoy per email
const decoyKey = process.env.SECURITY_QUESTION_DECOY_KEY ?? randomBytes(32).toString('hex')

// Unknown emails get a stable, keyed pseudo-random question so the response cannot reveal whether an account exists.
// The raw email is hashed (no normalization) because the account lookup is exact-match; normalizing would let
// variants of a registered email (padding, case) receive a decoy that differs from the real question.
async function decoyQuestionFor (email: string) {
  const questions = await SecurityQuestionModel.findAll({ order: [['id', 'ASC']] })
  if (questions.length === 0) {
    return null
  }
  const digest = createHmac('sha256', decoyKey).update(email).digest()
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
      const question = answer != null
        ? await SecurityQuestionModel.findByPk(answer.SecurityQuestionId)
        : await decoyQuestionFor(email?.toString() ?? '')
      res.json({ question })
    } catch (error) {
      next(error)
    }
  }
}
