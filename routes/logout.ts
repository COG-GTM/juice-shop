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
    const cookie = req.cookies?.token
    const bearerUserId = security.authenticatedUsers.get(bearer)?.data?.id
    security.revokeToken(bearer)
    if (cookie && cookie !== bearer && (bearer === undefined || security.authenticatedUsers.get(cookie)?.data?.id === bearerUserId)) {
      security.revokeToken(cookie)
    }
    security.clearSessionCookie(res)
    res.status(204).send()
  }
}
