/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import * as security from '../lib/insecurity'

const PUBLIC_USER_FIELDS = ['id', 'email', 'lastLoginIp', 'profileImage'] as const

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
        const allowedFields = PUBLIC_USER_FIELDS.filter(field => requestedFields.includes(field))

        let baseUser: any = {}

        if (requestedFields.length > 0) {
          for (const field of allowedFields) {
            if (user?.data[field] !== undefined) {
              baseUser[field] = user?.data[field]
            }
          }
        } else {
          baseUser = {
            id: user?.data?.id,
            email: user?.data?.email,
            lastLoginIp: user?.data?.lastLoginIp,
            profileImage: user?.data?.profileImage
          }
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
