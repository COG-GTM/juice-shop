/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

const selectableFields = ['id', 'email', 'lastLoginIp', 'profileImage'] as const

type SelectableField = typeof selectableFields[number]

export function retrieveLoggedInUser () {
  return (req: Request, res: Response) => {
    let user
    let response: any
    const emptyUser = { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined }
    try {
      if (security.verify(req.cookies.token)) {
        user = security.authenticatedUsers.get(req.cookies.token)

        const fieldsParam = req.query?.fields as string | undefined
        const requestedFields = fieldsParam
          ? fieldsParam.split(',').map(field => field.trim()).filter((field): field is SelectableField => (selectableFields as readonly string[]).includes(field))
          : []
        const returnedFields: readonly SelectableField[] = requestedFields.length > 0 ? requestedFields : selectableFields

        const baseUser: Partial<Record<SelectableField, unknown>> = {}
        for (const field of returnedFields) {
          baseUser[field] = user?.data?.[field]
        }

        response = { user: baseUser }
      } else {
        response = { user: emptyUser }
      }
    } catch (err) {
      response = { user: emptyUser }
    }
    // Solve passwordHashLeakChallenge when password field is included in response
    challengeUtils.solveIf(challenges.passwordHashLeakChallenge, () => response?.user?.password)

    if (req.query.callback === undefined) {
      res.json(response)
    } else {
      challengeUtils.solveIf(challenges.emailLeakChallenge, () => { return true })
      res.jsonp(response)
    }
  }
}
