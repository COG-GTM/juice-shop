/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

// Hints are shared instance state that the Score Board unlocks anonymously, so the only permitted update is { unlocked: true }
export function restrictHintUpdate () {
  return (req: Request, res: Response, next: NextFunction) => {
    const keys = Object.keys(req.body ?? {})
    if (keys.length === 1 && keys[0] === 'unlocked' && req.body.unlocked === true) {
      next()
    } else {
      res.status(403).json({ status: 'error', message: 'Only unlocking a hint is allowed.' })
    }
  }
}
