/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import jws from 'jws'

import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export const orderConfirmationsDirectory = 'orders'
const orderIdPattern = /^[0-9a-f]{4}-[0-9a-f]{16}$/

export function orderConfirmationPath (userId: number | undefined, orderId: string) {
  return path.resolve(orderConfirmationsDirectory, String(userId ?? 'anonymous'), `order_${orderId}.pdf`)
}

function isValidToken (token: string) {
  try {
    const decoded = jws.decode(token)
    const exp = decoded?.payload?.exp
    return decoded?.header?.alg === 'RS256' && security.verify(token) && (typeof exp !== 'number' || exp * 1000 > Date.now())
  } catch {
    return false
  }
}

function notFound (res: Response) {
  res.status(404).json({ status: 'error', message: 'Order confirmation not found' })
}

export function retrieveOrderConfirmation () {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = utils.unquote(utils.jwtFrom(req) ?? req.cookies?.token ?? '')
    const userId = isValidToken(token) ? security.authenticatedUsers.get(token)?.data?.id : undefined
    if (!userId) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }

    const orderId = req.params.orderId
    if (!orderIdPattern.test(orderId)) {
      notFound(res)
      return
    }

    res.set('Cache-Control', 'private, no-store')
    res.sendFile(`order_${orderId}.pdf`, { root: path.resolve(orderConfirmationsDirectory, String(userId)) }, (err: any) => {
      if (!err) return
      if (err.status === 404 || err.code === 'ENOENT') {
        res.removeHeader('Cache-Control')
        notFound(res)
      } else {
        next(err)
      }
    })
  }
}
