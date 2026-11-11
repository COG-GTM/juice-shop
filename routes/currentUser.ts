/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import * as security from '../lib/insecurity'

const allowedFields = ['id', 'email', 'lastLoginIp', 'profileImage'] as const
type AllowedField = typeof allowedFields[number]

export function retrieveLoggedInUser () {
  return (req: Request, res: Response) => {
    let response: any
    const emptyUser = { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined }
    try {
      if (security.verify(req.cookies.token)) {
        const user = security.authenticatedUsers.get(req.cookies.token)

        const fieldsParam = typeof req.query?.fields === 'string' ? req.query.fields : undefined
        const requestedFields = fieldsParam
          ? fieldsParam.split(',').map(f => f.trim()).filter((f): f is AllowedField => (allowedFields as readonly string[]).includes(f))
          : []
        const fields: readonly AllowedField[] = requestedFields.length > 0 ? requestedFields : allowedFields

        const baseUser: Partial<Record<AllowedField, unknown>> = {}
        for (const field of fields) {
          baseUser[field] = user?.data?.[field]
        }

        response = { user: baseUser }
      } else {
        response = { user: emptyUser }
      }
    } catch (err) {
      response = { user: emptyUser }
    }
    res.json(response)
  }
}
