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

function isCrossOriginRequest (req: Request) {
  const source = req.headers.origin ?? req.headers.referer
  if (!source) {
    return false
  }
  if (!req.headers.host) {
    return true
  }
  try {
    return new URL(source).host !== req.headers.host
  } catch {
    return true
  }
}

export function updateUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)

    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    if (req.body.username !== undefined && typeof req.body.username !== 'string') {
      res.status(400).json({ error: 'Invalid username' })
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

      if (isCrossOriginRequest(req)) {
        res.status(403).json({ error: 'Cross-origin profile update rejected' })
        return
      }

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
