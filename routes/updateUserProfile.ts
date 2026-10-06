/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const MAX_USERNAME_LENGTH = 100

export function isValidUsername (username: unknown): username is string {
  return typeof username === 'string' &&
    username.length <= MAX_USERNAME_LENGTH &&
    /^[\p{L}\p{M}\p{N}\p{P}\p{S} ]*$/u.test(username)
}

export function updateUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)

    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    if (!isValidUsername(req.body.username)) {
      res.status(400).send('Invalid username')
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        next(new Error('User not found'))
        return
      }

      challengeUtils.solveIf(challenges.csrfChallenge, () => {
        return ((req.headers.origin?.includes('://htmledit.squarefree.com')) ??
          (req.headers.referer?.includes('://htmledit.squarefree.com'))) &&
          req.body.username !== user.username
      })

      const savedUser = await user.update({ username: req.body.username })
      const userWithStatus = utils.queryResultToJson(savedUser)
      const updatedToken = security.authorize(userWithStatus)
      security.authenticatedUsers.put(updatedToken, userWithStatus)
      res.cookie('token', updatedToken)
      res.location(process.env.BASE_PATH + '/profile')
      res.redirect(process.env.BASE_PATH + '/profile')
    } catch (error) {
      next(error)
    }
  }
}
