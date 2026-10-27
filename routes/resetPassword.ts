/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { SecurityAnswerModel } from '../models/securityAnswer'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges, users } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

const MAX_FAILED_ATTEMPTS = 5
const LOCKOUT_DURATION_MS = 15 * 60 * 1000
const MAX_TRACKED_ACCOUNTS = 10000
const failedAttempts = new Map<string, { count: number, lockedUntil: number }>()

function isLockedOut (key: string) {
  const entry = failedAttempts.get(key)
  if (!entry) return false
  if (entry.lockedUntil > Date.now()) return true
  if (entry.lockedUntil !== 0) failedAttempts.delete(key)
  return false
}

function registerFailedAttempt (key: string) {
  if (!failedAttempts.has(key) && failedAttempts.size >= MAX_TRACKED_ACCOUNTS) {
    const oldestKey = failedAttempts.keys().next().value
    if (oldestKey !== undefined) failedAttempts.delete(oldestKey)
  }
  const entry = failedAttempts.get(key) ?? { count: 0, lockedUntil: 0 }
  entry.count++
  if (entry.count >= MAX_FAILED_ATTEMPTS) {
    entry.count = 0
    entry.lockedUntil = Date.now() + LOCKOUT_DURATION_MS
  }
  failedAttempts.set(key, entry)
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
    const attemptKey = String(email).toLowerCase()
    if (isLockedOut(attemptKey)) {
      res.status(429).send(res.__('Too many failed attempts. Please try again later.'))
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
          failedAttempts.delete(attemptKey)
          const updatedUser = await user.update({ password: newPassword })
          verifySecurityAnswerChallenges(updatedUser)
          res.json({ status: 'success' })
        }
      } else {
        registerFailedAttempt(attemptKey)
        res.status(401).send(res.__('Wrong answer to security question.'))
      }
    } catch (error) {
      next(error)
    }
  }
}

function verifySecurityAnswerChallenges (user: UserModel) {
  challengeUtils.solveIf(challenges.resetPasswordJimChallenge, () => { return user.id === users.jim.id })
  challengeUtils.solveIf(challenges.resetPasswordBenderChallenge, () => { return user.id === users.bender.id })
  challengeUtils.solveIf(challenges.resetPasswordBjoernChallenge, () => { return user.id === users.bjoern.id })
  challengeUtils.solveIf(challenges.resetPasswordMortyChallenge, () => { return user.id === users.morty.id })
  challengeUtils.solveIf(challenges.resetPasswordBjoernOwaspChallenge, () => { return user.id === users.bjoernOwasp.id })
  challengeUtils.solveIf(challenges.resetPasswordUvoginChallenge, () => { return user.id === users.uvogin.id })
  challengeUtils.solveIf(challenges.geoStalkingMetaChallenge, () => { return user.id === users.john.id })
  challengeUtils.solveIf(challenges.geoStalkingVisualChallenge, () => { return user.id === users.emma.id })
}
