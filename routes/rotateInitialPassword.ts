/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketModel } from '../models/basket'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'
import { beginPasswordRotation, clearPasswordChangeRequirement, endPasswordRotation, isPasswordChangeRequired } from '../lib/passwordRotation'

const MIN_PASSWORD_LENGTH = 12
const MAX_PASSWORD_LENGTH = 40
const ROTATION_TOKEN_LIFETIME_SECONDS = 15 * 60

export function rotateInitialPassword () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const { tmpToken, new: newPassword, repeat } = req.body ?? {}

    let userId: number | undefined
    try {
      const payload = security.verify(tmpToken) && security.decode(tmpToken)
      if (payload?.type !== 'password_valid_needs_rotation' || typeof payload.iat !== 'number' || Date.now() / 1000 - payload.iat > ROTATION_TOKEN_LIFETIME_SECONDS) {
        throw new Error('Invalid token type')
      }
      userId = payload.userId
    } catch {
      res.status(401).send(res.__('Invalid email or password.'))
      return
    }

    if (typeof newPassword !== 'string' || newPassword.length < MIN_PASSWORD_LENGTH || newPassword.length > MAX_PASSWORD_LENGTH) {
      res.status(400).send(res.__('Password must be between {{min}} and {{max}} characters long.', { min: String(MIN_PASSWORD_LENGTH), max: String(MAX_PASSWORD_LENGTH) }))
      return
    }
    if (newPassword !== repeat) {
      res.status(400).send(res.__('New and repeated password do not match.'))
      return
    }

    try {
      const user = await UserModel.findByPk(userId)
      if (!user || !isPasswordChangeRequired(user.id)) {
        res.status(401).send(res.__('Invalid email or password.'))
        return
      }
      if (user.password === security.hash(newPassword)) {
        res.status(400).send(res.__('New password must differ from the initial password.'))
        return
      }

      if (!beginPasswordRotation(user.id)) {
        res.status(409).send(res.__('Invalid email or password.'))
        return
      }
      try {
        await user.update({ password: newPassword })
        clearPasswordChangeRequirement(user.id)
      } finally {
        endPasswordRotation(user.id)
      }

      const plainUser = utils.queryResultToJson(user)
      const [basket] = await BasketModel.findOrCreate({ where: { UserId: user.id } })
      const token = security.authorize(plainUser)
      // @ts-expect-error FIXME set new property for original basket
      plainUser.bid = basket.id
      security.authenticatedUsers.put(token, plainUser)

      res.set('Cache-Control', 'no-store')
      res.json({ authentication: { token, bid: basket.id, umail: user.email } })
    } catch (error) {
      next(error)
    }
  }
}
