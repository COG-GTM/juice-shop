/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

const privilegedFields = ['role', 'deluxeToken', 'isActive', 'totpSecret', 'lastLoginIp']

export function sanitizeUserRegistration () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.body && typeof req.body === 'object') {
      for (const field of privilegedFields) {
        delete req.body[field]
      }
    }
    next()
  }
}
