/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import crypto from 'node:crypto'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

function isSameOrigin (req: Request) {
  const source = req.headers.origin ?? req.headers.referer
  if (!source) {
    return true
  }
  try {
    return new URL(source).host === req.headers.host
  } catch {
    return false
  }
}

function hasValidCsrfToken (req: Request) {
  const supplied = Buffer.from(typeof req.body?.csrf === 'string' ? req.body.csrf : '')
  const expected = Buffer.from(security.csrfTokenFor(req.cookies.token))
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected)
}

export function updateUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)

    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    if (!isSameOrigin(req) || !hasValidCsrfToken(req)) {
      res.status(403).send('Invalid CSRF token or cross-site request')
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
      res.cookie('token', updatedToken, { sameSite: 'strict' })
      res.location(process.env.BASE_PATH + '/profile')
      res.redirect(process.env.BASE_PATH + '/profile')
    } catch (error) {
      next(error)
    }
  }
}
