/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import * as security from '../lib/insecurity'

const returnableFields = ['id', 'email', 'lastLoginIp', 'profileImage'] as const

export function retrieveLoggedInUser () {
  return (req: Request, res: Response) => {
    let user
    let response: any
    const emptyUser = { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined }
    try {
      if (security.verify(req.cookies.token)) {
        user = security.authenticatedUsers.get(req.cookies.token)

        const fieldsParam = typeof req.query?.fields === 'string' ? req.query.fields : undefined
        const requestedFields = fieldsParam ? fieldsParam.split(',').map(f => f.trim()) : []
        const selectedFields = requestedFields.length > 0
          ? returnableFields.filter(field => requestedFields.includes(field))
          : returnableFields

        const baseUser: Record<string, unknown> = {}
        for (const field of selectedFields) {
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
