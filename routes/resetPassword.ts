/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response, type NextFunction } from 'express'

import type { Memory as MemoryConfig } from '../lib/config.types'
import { SecurityAnswerModel } from '../models/securityAnswer'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges, users } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

const MAX_FAILED_ATTEMPTS = 5
const ATTEMPT_WINDOW = 15 * 60 * 1000
const BASE_LOCKOUT = 60 * 1000

interface FailedAttempts {
  count: number
  lastAttempt: number
  lockedUntil: number
}

const failedAttemptsByEmail = new Map<string, FailedAttempts>()

function getFailedAttempts (email: string) {
  const attempts = failedAttemptsByEmail.get(email)
  if (!attempts || Date.now() - attempts.lastAttempt > ATTEMPT_WINDOW) {
    return { count: 0, lastAttempt: 0, lockedUntil: 0 }
  }
  return attempts
}

function registerFailedAttempt (email: string) {
  const attempts = getFailedAttempts(email)
  attempts.count++
  attempts.lastAttempt = Date.now()
  if (attempts.count >= MAX_FAILED_ATTEMPTS) {
    attempts.lockedUntil = attempts.lastAttempt + BASE_LOCKOUT * Math.pow(2, attempts.count - MAX_FAILED_ATTEMPTS)
  }
  failedAttemptsByEmail.set(email, attempts)
}

export function resetPassword () {
  return async ({ body, connection }: Request, res: Response, next: NextFunction) => {
    const email = body.email
    const answer = body.answer
    const newPassword = body.new
    const repeatPassword = body.repeat
    if (!email || !answer) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }
    if (!newPassword || newPassword === 'undefined') {
      res.status(401).send(res.__('Password cannot be empty.'))
      return
    }
    if (newPassword !== repeatPassword) {
      res.status(401).send(res.__('New and repeated password do not match.'))
      return
    }
    const lockedFor = getFailedAttempts(email).lockedUntil - Date.now()
    if (lockedFor > 0) {
      res.set('Retry-After', Math.ceil(lockedFor / 1000).toString())
      res.status(429).send(res.__('Too many failed attempts to answer the security question. Please try again later.'))
      return
    }
    try {
      const data = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email }
        }]
      })
      if ((data != null) && security.hmac(answer) === data.answer) {
        const user = await UserModel.findByPk(data.UserId)
        if (user) {
          const updatedUser = await user.update({ password: newPassword })
          failedAttemptsByEmail.delete(email)
          verifySecurityAnswerChallenges(updatedUser, answer)
          res.json({ user: updatedUser })
        }
      } else {
        registerFailedAttempt(email)
        res.status(401).send(res.__('Wrong answer to security question.'))
      }
    } catch (error) {
      next(error)
    }
  }
}

function verifySecurityAnswerChallenges (user: UserModel, answer: string) {
  challengeUtils.solveIf(challenges.resetPasswordJimChallenge, () => { return user.id === users.jim.id && answer === 'Samuel' })
  challengeUtils.solveIf(challenges.resetPasswordBenderChallenge, () => { return user.id === users.bender.id && answer === 'Stop\'n\'Drop' })
  challengeUtils.solveIf(challenges.resetPasswordBjoernChallenge, () => { return user.id === users.bjoern.id && answer === 'West-2082' })
  challengeUtils.solveIf(challenges.resetPasswordMortyChallenge, () => { return user.id === users.morty.id && answer === '5N0wb41L' })
  challengeUtils.solveIf(challenges.resetPasswordBjoernOwaspChallenge, () => { return user.id === users.bjoernOwasp.id && answer === 'Zaya' })
  challengeUtils.solveIf(challenges.resetPasswordUvoginChallenge, () => { return user.id === users.uvogin.id && answer === 'Silence of the Lambs' })
  challengeUtils.solveIf(challenges.geoStalkingMetaChallenge, () => {
    const securityAnswer = ((() => {
      const memories = config.get<MemoryConfig[]>('memories')
      for (let i = 0; i < memories.length; i++) {
        if (memories[i].geoStalkingMetaSecurityAnswer) {
          return memories[i].geoStalkingMetaSecurityAnswer
        }
      }
    })())
    return user.id === users.john.id && answer === securityAnswer
  })
  challengeUtils.solveIf(challenges.geoStalkingVisualChallenge, () => {
    const securityAnswer = ((() => {
      const memories = config.get<MemoryConfig[]>('memories')
      for (let i = 0; i < memories.length; i++) {
        if (memories[i].geoStalkingVisualSecurityAnswer) {
          return memories[i].geoStalkingVisualSecurityAnswer
        }
      }
    })())
    return user.id === users.emma.id && answer === securityAnswer
  })
}
