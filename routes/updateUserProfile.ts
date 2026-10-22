/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const USERNAME_PATTERN = /^[\p{L}\p{M}\p{N} ._-]{0,64}$/u

function isSameOriginRequest (req: Request) {
  const source = req.headers.origin ?? req.headers.referer
  if (source === undefined) {
    return false
  }
  try {
    const { protocol, host } = new URL(source)
    return host === req.get('host') && (protocol === `${req.protocol}:` || protocol === 'https:')
  } catch {
    return false
  }
}

export function updateUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)

    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    if (!isSameOriginRequest(req)) {
      res.status(403).send('Cross-origin profile updates are not allowed')
      return
    }

    const username = req.body?.username
    if (typeof username !== 'string' || !USERNAME_PATTERN.test(username)) {
      res.status(400).send('Username may only contain letters, digits, spaces, dots, underscores and hyphens (max. 64 characters)')
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        next(new Error('User not found'))
        return
      }

      const savedUser = await user.update({ username })
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
