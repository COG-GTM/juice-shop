/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'

import { SecurityAnswerModel } from '../models/securityAnswer'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges, users } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import logger from '../lib/logger'

const RESET_TOKEN_TTL_MS = 15 * 60 * 1000

type PasswordResetMailer = (email: string, token: string) => void | Promise<void>

const defaultMailer: PasswordResetMailer = (email) => {
  logger.warn(`No password reset mailer configured; reset token for ${email} was not delivered`)
}

let mailer: PasswordResetMailer = defaultMailer

export function setPasswordResetMailer (newMailer?: PasswordResetMailer) {
  mailer = newMailer ?? defaultMailer
}

const resetTokens = new Map<number, { tokenHash: Buffer, expiresAt: number }>()

function hashToken (token: string) {
  return crypto.createHash('sha256').update(token).digest()
}

function consumeResetToken (userId: number, token: unknown) {
  const entry = resetTokens.get(userId)
  if (!entry || typeof token !== 'string' || !token) return false
  if (Date.now() > entry.expiresAt) {
    resetTokens.delete(userId)
    return false
  }
  if (!crypto.timingSafeEqual(entry.tokenHash, hashToken(token))) return false
  resetTokens.delete(userId)
  return true
}

export function requestPasswordReset () {
  return async ({ body }: Request, res: Response, next: NextFunction) => {
    const email = body?.email
    if (!email || typeof email !== 'string') {
      res.status(400).send(res.__('Email address is required.'))
      return
    }
    try {
      const user = await UserModel.findOne({ where: { email } })
      if (user) {
        const token = crypto.randomBytes(32).toString('hex')
        resetTokens.set(user.id, { tokenHash: hashToken(token), expiresAt: Date.now() + RESET_TOKEN_TTL_MS })
        await mailer(user.email, token)
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
    const token = body.token
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
      if ((data != null) && security.hmac(answer) === data.answer) {
        if (!consumeResetToken(data.UserId, token)) {
          res.status(401).send(res.__('Invalid or expired password reset token.'))
          return
        }
        const user = await UserModel.findByPk(data.UserId)
        if (user) {
          const updatedUser = await user.update({ password: newPassword })
          verifySecurityAnswerChallenges(updatedUser)
          res.json({ user: updatedUser })
        }
      } else {
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
