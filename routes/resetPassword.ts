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
const PRUNE_THRESHOLD = 10000
const attempts = new Map<number, { count: number, expiresAt: number }>()

function pruneExpiredAttempts (now: number) {
  for (const [userId, entry] of attempts) {
    if (entry.expiresAt <= now) attempts.delete(userId)
  }
}

function registerAttempt (userId: number) {
  const now = Date.now()
  if (attempts.size >= PRUNE_THRESHOLD) pruneExpiredAttempts(now)
  let entry = attempts.get(userId)
  if (entry && entry.expiresAt <= now) entry = undefined
  if (entry && entry.count >= MAX_FAILED_ATTEMPTS) return false
  if (!entry) {
    entry = { count: 0, expiresAt: 0 }
    attempts.set(userId, entry)
  }
  entry.count++
  entry.expiresAt = now + LOCKOUT_DURATION_MS
  return true
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
    try {
      const data = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email }
        }]
      })
      if (data == null) {
        res.status(401).send(res.__('Wrong answer to security question.'))
        return
      }
      if (!registerAttempt(data.UserId)) {
        res.status(429).send(res.__('Too many failed attempts. Please try again later.'))
        return
      }
      if (security.hmac(answer) !== data.answer) {
        res.status(401).send(res.__('Wrong answer to security question.'))
        return
      }
      attempts.delete(data.UserId)
      const user = await UserModel.findByPk(data.UserId)
      if (user) {
        const updatedUser = await user.update({ password: newPassword })
        verifySecurityAnswerChallenges(updatedUser)
        res.json({ status: 'success' })
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
