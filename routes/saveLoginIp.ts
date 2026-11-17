/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { isIP } from 'node:net'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const toValidIp = (address?: string) => {
  if (address === undefined || isIP(address) === 0) {
    return undefined
  }
  const simpleAddress = utils.toSimpleIpAddress(address)
  return isIP(simpleAddress) !== 0 ? simpleAddress : address
}

export function saveLoginIp () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (loggedInUser !== undefined) {
      const lastLoginIp = security.sanitizeSecure(toValidIp(req.ip) ?? toValidIp(req.socket.remoteAddress) ?? '')
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
