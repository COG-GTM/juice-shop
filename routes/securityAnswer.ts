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

async function parseSecurityAnswer (questionRef: unknown, answer: unknown): Promise<PendingSecurityAnswer | null> {
  const questionId = Number(typeof questionRef === 'object' && questionRef !== null ? (questionRef as { id?: unknown }).id : questionRef)
  if (!Number.isInteger(questionId) || typeof answer !== 'string' || answer.trim() === '') return null
  if (await SecurityQuestionModel.findByPk(questionId) == null) return null
  return { SecurityQuestionId: questionId, answer }
}

export function validateRegistrationSecurityAnswer () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const { securityQuestion, securityAnswer } = req.body ?? {}
    if (res.headersSent || (securityQuestion == null && securityAnswer == null)) {
      next()
      return
    }
    const pending = await parseSecurityAnswer(securityQuestion, securityAnswer)
    if (pending == null) {
      return res.status(400).json({ status: 'error', message: 'Invalid security question or answer.' })
    }
    res.locals.pendingSecurityAnswer = pending
    next()
  }
}

export function saveRegistrationSecurityAnswer () {
  return async (req: Request, res: Response, context: { instance: { id: number, destroy: (options: { force: boolean }) => Promise<void> }, continue: any }) => {
    const pending: PendingSecurityAnswer | undefined = res.locals.pendingSecurityAnswer
    if (pending != null) {
      try {
        await SecurityAnswerModel.create({ UserId: context.instance.id, ...pending })
      } catch (err) {
        await context.instance.destroy({ force: true })
        throw err
      }
    }
    return context.continue
  }
}
