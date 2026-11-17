/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import config from 'config'
import { Op } from 'sequelize'
import { type Request, type Response, type NextFunction } from 'express'

import { PasswordResetTokenModel } from '../models/passwordResetToken'
import { UserModel } from '../models/user'
import * as mailer from '../lib/mailer'
import logger from '../lib/logger'

const TOKEN_TTL_MS = 15 * 60 * 1000

const hashToken = (token: string) => crypto.createHash('sha256').update(token).digest('hex')

export function requestPasswordReset () {
  return async ({ body }: Request, res: Response, next: NextFunction) => {
    const email = body.email
    if (typeof email !== 'string' || !email) {
      res.status(400).send(res.__('Email address cannot be empty.'))
      return
    }
    try {
      const user = await UserModel.findOne({ where: { email } })
      if (user) {
        await PasswordResetTokenModel.destroy({ where: { UserId: user.id, usedAt: null } })
        const token = crypto.randomBytes(32).toString('base64url')
        await PasswordResetTokenModel.create({
          UserId: user.id,
          tokenHash: hashToken(token),
          expiresAt: new Date(Date.now() + TOKEN_TTL_MS)
        })
        const resetLink = `${config.get<string>('server.baseUrl')}${process.env.BASE_PATH ?? ''}/#/forgot-password?token=${token}`
        mailer.sendMail({
          to: user.email,
          subject: `${config.get<string>('application.name')} password reset`,
          text: `Use this link within 15 minutes to reset your password:\n\n${resetLink}\n\nIf you did not request a password reset, you can ignore this email.`
        }).catch((error: Error) => { logger.error(`Failed to send password reset email: ${error.message}`) })
      }
      res.json({ status: 'success' })
    } catch (error) {
      next(error)
    }
  }
}

export function resetPassword () {
  return async ({ body, connection }: Request, res: Response, next: NextFunction) => {
    const token = body.token
    const newPassword = body.new
    const repeatPassword = body.repeat
    if (typeof token !== 'string' || !token) {
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
      const resetToken = await PasswordResetTokenModel.findOne({
        where: { tokenHash: hashToken(token), usedAt: null, expiresAt: { [Op.gt]: new Date() } }
      })
      const [claimed] = resetToken
        ? await PasswordResetTokenModel.update({ usedAt: new Date() }, { where: { id: resetToken.id, usedAt: null } })
        : [0]
      const user = (resetToken && claimed === 1) ? await UserModel.findByPk(resetToken.UserId) : null
      if (!user) {
        res.status(401).send(res.__('Invalid or expired password reset link.'))
        return
      }
      await user.update({ password: newPassword })
      res.json({ user: { id: user.id, email: user.email } })
    } catch (error) {
      next(error)
    }
  }
}
