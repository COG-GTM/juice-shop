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

export function saveLoginIp (trustedProxies?: readonly string[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (loggedInUser !== undefined) {
      let trueClientIp = req.headers['true-client-ip']
      if (Array.isArray(trueClientIp)) {
        trueClientIp = trueClientIp[0]
      }
      if (utils.isChallengeEnabled(challenges.httpHeaderXssChallenge)) {
        challengeUtils.solveIf(challenges.httpHeaderXssChallenge, () => { return trueClientIp === '<iframe src="javascript:alert(`xss`)">' })
      }
      const remoteAddress = req.socket.remoteAddress ?? ''
      const clientIp = typeof trueClientIp === 'string' && isIP(trueClientIp) !== 0 && utils.isTrustedProxy(remoteAddress, trustedProxies) ? trueClientIp : remoteAddress
      const lastLoginIp = utils.toSimpleIpAddress(clientIp)
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        const updatedUser = await user?.update({ lastLoginIp })
        res.json({ lastLoginIp: updatedUser?.lastLoginIp })
      } catch (error) {
        next(error)
      }
    } else {
      res.sendStatus(401)
    }
  }
}
