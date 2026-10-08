/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

export const registrationAttributes = ['email', 'password', 'passwordRepeat', 'securityQuestion', 'securityAnswer'] as const

export function restrictRegistrationAttributes () {
  return (req: Request, res: Response, next: NextFunction) => {
    const body = req.body
    if (body !== null && typeof body === 'object' && !Array.isArray(body)) {
      const allowed: Record<string, unknown> = {}
      for (const attribute of registrationAttributes) {
        if (Object.prototype.hasOwnProperty.call(body, attribute)) {
          allowed[attribute] = body[attribute]
        }
      }
      req.body = allowed
    } else {
      req.body = {}
    }
    next()
  }
}
