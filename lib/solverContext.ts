/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { AsyncLocalStorage } from 'node:async_hooks'
import { type Request, type Response, type NextFunction } from 'express'
import jws from 'jws'
import * as security from './insecurity'
import * as utils from './utils'

interface SolverContext {
  token?: string
  userId?: number
  resolved?: boolean
}

const storage = new AsyncLocalStorage<SolverContext>()

export const socketUserIds = new WeakMap<object, number>()

export const tokenFromCookieHeader = (cookieHeader?: string) => {
  const cookie = cookieHeader?.split(';').map(c => c.trim()).find(c => c.startsWith('token='))
  if (!cookie) return undefined
  try {
    return decodeURIComponent(cookie.substring('token='.length))
  } catch {
    return undefined
  }
}

export const userIdFromToken = (token: unknown): number | undefined => {
  if (typeof token !== 'string' || token.length === 0) return undefined
  try {
    const decoded = jws.decode(token)
    if (decoded?.header?.alg !== 'RS256' || !security.verify(token)) return undefined
    const payload = typeof decoded.payload === 'string' ? JSON.parse(decoded.payload) : decoded.payload
    if (typeof payload?.exp === 'number' && payload.exp * 1000 < Date.now()) return undefined
    const id = payload?.data?.id
    return typeof id === 'number' ? id : undefined
  } catch {
    return undefined
  }
}

export const middleware = () => (req: Request, res: Response, next: NextFunction) => {
  storage.run({ token: utils.jwtFrom(req) ?? tokenFromCookieHeader(req.headers?.cookie) }, next)
}

export const runAs = <T>(userId: number | undefined, fn: () => T): T => storage.run({ userId, resolved: true }, fn)

export const currentSolverId = (): number | undefined => {
  const context = storage.getStore()
  if (!context) return undefined
  if (!context.resolved) {
    context.userId = userIdFromToken(context.token)
    context.resolved = true
  }
  return context.userId
}
