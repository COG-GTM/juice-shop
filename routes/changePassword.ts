/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function changePassword () {
  return async ({ query, headers, connection }: Request, res: Response, next: NextFunction) => {
    const currentPassword = query.current as string
    const newPassword = query.new as string
    const newPasswordInString = newPassword?.toString()
    const repeatPassword = query.repeat

    if (!newPassword || newPassword === 'undefined') {
      res.status(401).send(res.__('Password cannot be empty.'))
      return
    } else if (newPassword !== repeatPassword) {
      res.status(401).send(res.__('New and repeated password do not match.'))
      return
    }

    const token = headers.authorization ? utils.unquote(headers.authorization.substr('Bearer='.length)) : null
    const loggedInUser = token ? security.authenticatedUsers.get(token) : undefined
    const verifiedUser = token ? security.verifiedPayload(token) : null
    if (!token || !loggedInUser || !verifiedUser || verifiedUser.data.id !== loggedInUser.data.id) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }

    try {
      const user = await UserModel.findByPk(verifiedUser.data.id)
      if (!user) {
        res.status(404).send(res.__('User not found.'))
        return
      }

      if (!currentPassword || security.hash(currentPassword) !== user.password) {
        res.status(401).send(res.__('Current password is not correct.'))
        return
      }

      await user.update({ password: newPasswordInString })
      for (const [otherToken, entry] of Object.entries(security.authenticatedUsers.tokenMap)) {
        if (otherToken !== token && entry?.data?.id === user.id) {
          delete security.authenticatedUsers.tokenMap[otherToken]
        }
      }
      security.authenticatedUsers.idMap[user.id] = token
      res.json({ user })
    } catch (error) {
      next(error)
    }
  }
}
