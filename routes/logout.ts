/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function logout () {
  return (req: Request, res: Response) => {
    const token = utils.jwtFrom(req)
    if (!token || !security.verify(token)) {
      res.status(401).json({ status: 'error', message: 'Session has ended. Please log in again.' })
      return
    }
    security.authenticatedUsers.revoke(token)
    res.clearCookie('token')
    res.status(204).send()
  }
}
