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
    if (token && security.verify(token)) {
      security.authenticatedUsers.revoke(token)
      const userId = security.decode(token)?.data?.id
      for (const other of [req.cookies?.token, req.body?.token]) {
        if (typeof other === 'string' && other !== token && security.verify(other) && security.decode(other)?.data?.id === userId) {
          security.authenticatedUsers.revoke(other)
        }
      }
    }
    res.status(204).send()
  }
}
