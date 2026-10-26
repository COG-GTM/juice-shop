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
import * as passwordReset from '../lib/passwordReset'

export function requestPasswordReset () {
  return async ({ body }: Request, res: Response, next: NextFunction) => {
    const email = body.email
    if (typeof email !== 'string' || !email) {
      res.status(400).send(res.__('Email address is required.'))
      return
    }
    try {
      const user = await UserModel.findOne({ where: { email } })
      if (user) {
        await passwordReset.issueResetToken(user.id, user.email)
      }
      res.json({ status: 'success' })
    } catch (error) {
      next(error)
    }
  }
}

export function resetPassword () {
  return async ({ body, connection }: Request, res: Response, next: NextFunction) => {
    const email = body.email
    const answer = body.answer
    const newPassword = body.new
    const repeatPassword = body.repeat
    const token = body.token
    if (!email || !answer || typeof email !== 'string' || typeof answer !== 'string') {
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
    if (passwordReset.isLockedOut(email)) {
      res.status(429).send(res.__('Too many failed password reset attempts. Please try again later.'))
      return
    }
    try {
      const data = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email }
        }]
      })
      if (data == null || typeof token !== 'string' || !passwordReset.isValidResetToken(token, data.UserId)) {
        passwordReset.registerFailedAttempt(email)
        res.status(401).send(res.__('Invalid or expired password reset code.'))
        return
      }
      if (security.hmac(answer) !== data.answer) {
        passwordReset.registerFailedAttempt(email)
        res.status(401).send(res.__('Wrong answer to security question.'))
        return
      }
      passwordReset.invalidateResetTokens(data.UserId)
      passwordReset.clearFailedAttempts(email)
      const user = await UserModel.findByPk(data.UserId)
      if (user) {
        const updatedUser = await user.update({ password: newPassword })
        security.revokeSessionsOf(user.id)
        verifySecurityAnswerChallenges(updatedUser, answer)
        res.json({ user: updatedUser })
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
