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
const MAX_TRACKED_ACCOUNTS = 10000

interface ResetAttempts {
  failures: number
  windowStart: number
  lockedUntil: number
}

const resetAttempts = new Map<string, ResetAttempts>()

function attemptKey (email: unknown) {
  return String(email).trim().toLowerCase()
}

function isLockedOut (key: string, now: number) {
  const attempts = resetAttempts.get(key)
  return attempts !== undefined && attempts.lockedUntil > now
}

function freeTrackingSlot (now: number) {
  for (const [key, attempts] of resetAttempts) {
    if (attempts.lockedUntil <= now && attempts.windowStart + LOCKOUT_DURATION_MS <= now) {
      resetAttempts.delete(key)
    }
  }
  for (const [key, attempts] of resetAttempts) {
    if (resetAttempts.size < MAX_TRACKED_ACCOUNTS) return
    if (attempts.lockedUntil <= now) resetAttempts.delete(key)
  }
}

function reserveAttempt (key: string, now: number) {
  if (!resetAttempts.has(key) && resetAttempts.size >= MAX_TRACKED_ACCOUNTS) {
    freeTrackingSlot(now)
    if (resetAttempts.size >= MAX_TRACKED_ACCOUNTS) return undefined
  }
  let attempts = resetAttempts.get(key)
  if (attempts === undefined || attempts.windowStart + LOCKOUT_DURATION_MS <= now) {
    attempts = { failures: 0, windowStart: now, lockedUntil: 0 }
    resetAttempts.set(key, attempts)
  }
  attempts.failures++
  if (attempts.failures >= MAX_FAILED_ATTEMPTS) {
    attempts.lockedUntil = now + LOCKOUT_DURATION_MS
  }
  return attempts
}

function releaseAttempt (key: string, attempts: ResetAttempts) {
  if (resetAttempts.get(key) !== attempts) return
  attempts.failures--
  if (attempts.failures < MAX_FAILED_ATTEMPTS) attempts.lockedUntil = 0
}

export function clearResetAttempts () {
  resetAttempts.clear()
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
    const key = attemptKey(email)
    const now = Date.now()
    const attempts = isLockedOut(key, now) ? undefined : reserveAttempt(key, now)
    if (attempts === undefined) {
      res.status(429).send(res.__('Too many failed attempts. Please try again later.'))
      return
    }
    let answerChecked = false
    try {
      const data = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email }
        }]
      })
      const correct = (data != null) && security.hmac(answer) === data.answer
      answerChecked = true
      if (correct) {
        resetAttempts.delete(key)
        const user = await UserModel.findByPk(data.UserId)
        if (user) {
          const updatedUser = await user.update({ password: newPassword })
          verifySecurityAnswerChallenges(updatedUser, answer)
          res.json({ user: updatedUser })
        }
      } else {
        res.status(401).send(res.__('Wrong answer to security question.'))
      }
    } catch (error) {
      if (!answerChecked) releaseAttempt(key, attempts)
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
