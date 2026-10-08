/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import config from 'config'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

function configuredHost () {
  try {
    return new URL(config.get<string>('server.baseUrl')).host
  } catch {
    return undefined
  }
}

// Browsers set Sec-Fetch-Site themselves, so it reflects the page origin even behind host-rewriting proxies
function isCrossSiteRequest (req: Request) {
  const fetchSite = req.get('sec-fetch-site')
  if (fetchSite !== undefined) {
    return fetchSite !== 'same-origin' && fetchSite !== 'none'
  }
  const source = req.headers.origin ?? req.headers.referer
  if (source === undefined) {
    return false
  }
  try {
    const sourceUrl = new URL(source)
    const requestHost = new URL(`${sourceUrl.protocol}//${req.headers.host}`).host
    return sourceUrl.host !== requestHost && sourceUrl.host !== configuredHost()
  } catch {
    return true
  }
}

const MAX_USERNAME_LENGTH = 255

function isValidUsername (username: unknown): username is string {
  // eslint-disable-next-line no-control-regex
  return typeof username === 'string' && username.length <= MAX_USERNAME_LENGTH && !/[\u0000-\u001f\u007f]/.test(username)
}

export function updateUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)

    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        next(new Error('User not found'))
        return
      }

      if (isCrossSiteRequest(req)) {
        res.status(403).json({ error: 'Cross-site profile update rejected' })
        return
      }

      if (!isValidUsername(req.body.username)) {
        res.status(400).json({ error: 'Invalid username' })
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
