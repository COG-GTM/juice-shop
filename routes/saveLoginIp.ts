/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { isIP } from 'node:net'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

export function saveLoginIp () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (loggedInUser !== undefined) {
      let trueClientIp = req.headers['true-client-ip']
      if (Array.isArray(trueClientIp)) {
        trueClientIp = trueClientIp[0]
      }
      const lastLoginIp = trueClientIp !== undefined && isIP(trueClientIp.trim()) !== 0
        ? trueClientIp.trim()
        : utils.toSimpleIpAddress(req.socket.remoteAddress ?? '')
      challengeUtils.solveIf(challenges.httpHeaderXssChallenge, () => { return lastLoginIp === '<iframe src="javascript:alert(`xss`)">' })
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        const updatedUser = await user?.update({ lastLoginIp })
        res.json(updatedUser)
      } catch (error) {
        next(error)
      }
    } else {
      res.sendStatus(401)
    }
  }
}
