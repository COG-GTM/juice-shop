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
const LOCKOUT_DURATION_MS = 15 * 60 * 1000
const MAX_TRACKED_EMAILS = 10000
const resetAttempts = new Map<string, { count: number, expiresAt: number }>()

function pruneExpiredAttempts (now: number) {
  for (const [key, entry] of resetAttempts) {
    if (entry.expiresAt <= now) resetAttempts.delete(key)
  }
}

function evictOldestUnlockedAttempt () {
  for (const [key, entry] of resetAttempts) {
    if (entry.count < MAX_FAILED_ATTEMPTS) {
      resetAttempts.delete(key)
      return true
    }
  }
  return false
}

// Counts the attempt before the async answer check so concurrent guesses cannot exceed the limit
function reserveResetAttempt (key: string) {
  const now = Date.now()
  let entry = resetAttempts.get(key)
  if (entry && entry.expiresAt <= now) {
    resetAttempts.delete(key)
    entry = undefined
  }
  if (!entry) {
    if (resetAttempts.size >= MAX_TRACKED_EMAILS) {
      pruneExpiredAttempts(now)
      if (resetAttempts.size >= MAX_TRACKED_EMAILS && !evictOldestUnlockedAttempt()) return false
    }
    entry = { count: 0, expiresAt: now + LOCKOUT_DURATION_MS }
    resetAttempts.set(key, entry)
  }
  if (entry.count >= MAX_FAILED_ATTEMPTS) return false
  entry.count++
  if (entry.count >= MAX_FAILED_ATTEMPTS) entry.expiresAt = now + LOCKOUT_DURATION_MS
  return true
}

function releaseResetAttempt (key: string) {
  const entry = resetAttempts.get(key)
  if (entry && entry.count > 0) entry.count--
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
    const lockoutKey = String(email).toLowerCase()
    if (!reserveResetAttempt(lockoutKey)) {
      res.status(429).send('Too many failed attempts. Please try again later.')
      return
    }
    let wrongAnswer = false
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
          resetAttempts.delete(lockoutKey)
          verifySecurityAnswerChallenges(updatedUser, answer)
          res.json({ status: 'success' })
        }
      } else {
        wrongAnswer = true
        res.status(401).send(res.__('Wrong answer to security question.'))
      }
    } catch (error) {
      if (!wrongAnswer) releaseResetAttempt(lockoutKey)
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
