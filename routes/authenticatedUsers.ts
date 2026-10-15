/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import { decode } from 'jsonwebtoken'
import * as security from '../lib/insecurity'

// req.user is the payload that security.isAuthorized() (express-jwt) has already signature-verified for this route
function isAdminRequest (req: Request & { user?: { data?: { role?: string } } }) {
  return req.user?.data?.role === security.roles.admin
}

async function retrieveUserList (req: Request, res: Response, next: NextFunction) {
  if (!isAdminRequest(req)) {
    res.status(403).json({ error: 'Admin role required' })
    return
  }
  try {
    const users = await UserModel.findAll({ attributes: ['id', 'email'] })

    res.json({
      status: 'success',
      data: users.map((user) => {
        const userToken = security.authenticatedUsers.tokenOf(user)
        let lastLoginTime: number | null = null
        if (userToken) {
          const parsedToken = decode(userToken, { json: true })
          lastLoginTime = parsedToken ? Math.floor(new Date(parsedToken?.iat ?? 0 * 1000).getTime()) : null
        }

        return {
          id: user.id,
          email: user.email,
          lastLoginTime
        }
      })
    })
  } catch (error) {
    next(error)
  }
}

export default () => retrieveUserList
