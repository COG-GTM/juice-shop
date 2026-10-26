/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

export function restrictHintUpdateToUnlocking () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.body?.unlocked !== true || Object.keys(req.body).some(key => key !== 'unlocked')) {
      res.status(403).json({ status: 'error', message: 'Only unlocking a hint is allowed.' })
      return
    }
    next()
  }
}
