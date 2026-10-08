/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

// The Score Board unlocks hints without login, so { unlocked: true } is the only update allowed through to finale
export function restrictHintUpdate () {
  return (req: Request, res: Response, next: NextFunction) => {
    const body = req.body
    const isUnlockOnly = body !== null && typeof body === 'object' && !Array.isArray(body) &&
      Object.keys(body).length === 1 && body.unlocked === true
    if (isUnlockOnly) {
      req.body = { unlocked: true }
      next()
    } else {
      res.status(403).json({ status: 'error', message: 'Only unlocking a hint is allowed.' })
    }
  }
}
