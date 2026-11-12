/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'

export function logout () {
  return (req: Request, res: Response) => {
    security.clearSessionCookie(res)
    res.status(204).send()
  }
}
