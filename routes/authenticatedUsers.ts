/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import { decode } from 'jsonwebtoken'
import * as security from '../lib/insecurity'

export const MAX_PAGE_SIZE = 100

function nonNegativeInteger (value: unknown): number | undefined {
  if (typeof value !== 'string' || !/^\d+$/.test(value)) return undefined
  return Math.min(Number(value), Number.MAX_SAFE_INTEGER)
}

export function paginationFrom (query: Request['query']) {
  const limit = nonNegativeInteger(query.limit)
  if (limit === undefined) return {}
  return {
    limit: Math.min(Math.max(limit, 1), MAX_PAGE_SIZE),
    offset: nonNegativeInteger(query.offset) ?? 0
  }
}

function lastLoginTimeOf (user: UserModel): number | null {
  const userToken = security.authenticatedUsers.tokenOf(user)
  if (!userToken) return null
  const parsedToken = decode(userToken, { json: true })
  return typeof parsedToken?.iat === 'number' ? parsedToken.iat : null
}

async function retrieveUserList (req: Request, res: Response, next: NextFunction) {
  try {
    const users = await UserModel.findAll({
      attributes: ['id', 'email'],
      order: [['id', 'ASC']],
      ...paginationFrom(req.query)
    })

    res.json({
      status: 'success',
      data: users.map((user) => ({
        id: user.id,
        email: user.email,
        lastLoginTime: lastLoginTimeOf(user)
      }))
    })
  } catch (error) {
    next(error)
  }
}

export default () => retrieveUserList
