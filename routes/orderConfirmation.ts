/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import jws from 'jws'

import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export const orderConfirmationsDirectory = 'orders'
const orderIdPattern = /^[0-9a-f]{4}-[0-9a-f]{16}$/

export function orderConfirmationPath (userId: number | undefined, orderId: string) {
  const baseDirectory = path.resolve(orderConfirmationsDirectory)
  const filePath = path.resolve(baseDirectory, String(userId ?? 'anonymous'), `order_${orderId}.pdf`)
  if (!filePath.startsWith(baseDirectory + path.sep)) {
    throw new Error('Invalid order confirmation path')
  }
  return filePath
}

async function findOrderConfirmation (userId: number, orderId: string) {
  const userDirectory = path.resolve(orderConfirmationsDirectory, String(userId))
  const fileName = `order_${orderId}.pdf`
  const files = await fs.promises.readdir(userDirectory).catch((err: NodeJS.ErrnoException) => {
    if (err.code === 'ENOENT') return [] as string[]
    throw err
  })
  const match = files.find(file => file === fileName)
  return match ? path.join(userDirectory, match) : undefined
}

function isValidToken (token: string) {
  try {
    const decoded = jws.decode(token)
    const payload = typeof decoded?.payload === 'string' ? JSON.parse(decoded.payload) : decoded?.payload
    const exp = payload?.exp
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

    void findOrderConfirmation(userId, orderId).then((filePath) => {
      if (!filePath) {
        notFound(res)
        return
      }
      res.set('Cache-Control', 'private, no-store')
      res.sendFile(filePath, (err: any) => {
        if (!err) return
        if (err.status === 404 || err.code === 'ENOENT') {
          res.removeHeader('Cache-Control')
          notFound(res)
        } else {
          next(err)
        }
      })
    }).catch(next)
  }
}
