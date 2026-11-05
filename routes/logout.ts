/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function logout () {
  return (req: Request, res: Response) => {
    const bearer = utils.jwtFrom(req)
    const userId = security.authenticatedUsers.get(bearer)?.data?.id
    if (!bearer || userId === undefined) {
      res.status(401).json({ status: 'error', message: 'Session has ended. Please log in again.' })
      return
    }
    const cookie = req.cookies?.token
    const sameUserCookie = !!cookie && (utils.unquote(cookie) === utils.unquote(bearer) || security.authenticatedUsers.get(cookie)?.data?.id === userId)
    security.authenticatedUsers.revoke(bearer)
    if (sameUserCookie) {
      security.authenticatedUsers.revoke(cookie)
      res.clearCookie('token')
    }
    res.status(204).send()
  }
}
