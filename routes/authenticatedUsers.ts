/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import { decode } from 'jsonwebtoken'
import * as security from '../lib/insecurity'

async function retrieveUserList (req: Request, res: Response, next: NextFunction) {
  try {
    const sessionUserId = security.authenticatedUsers.from(req)?.data?.id
    const sessionUser = sessionUserId !== undefined ? await UserModel.findByPk(sessionUserId, { attributes: ['role'] }) : null
    if (sessionUser?.role !== security.roles.admin) {
      res.status(403).json({ error: 'Malicious activity detected' })
      return
    }

    const users = await UserModel.findAll({ attributes: ['id', 'email'] })

    res.json({
      status: 'success',
      data: users.map((user) => {
        const userToken = security.authenticatedUsers.tokenOf(user)
        let lastLoginTime: number | null = null
        if (userToken) {
          const parsedToken = decode(userToken, { json: true })
          lastLoginTime = typeof parsedToken?.iat === 'number' ? parsedToken.iat : null
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
