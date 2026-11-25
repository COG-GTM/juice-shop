/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as models from '../models/index'
import * as security from '../lib/insecurity'

const DEFAULT_PAGE_SIZE = 10
const MAX_PAGE_SIZE = 50

const toPositiveInt = (value: unknown, fallback: number) => {
  const parsed = parseInt(String(value ?? ''), 10)
  return Number.isNaN(parsed) || parsed < 1 ? fallback : parsed
}

export function searchOrderItems () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = security.authenticatedUsers.from(req)
      if (!user?.data?.id) {
        res.status(401).json({ status: 'error', message: 'Unauthorized' })
        return
      }

      const q = typeof req.query.q === 'string' ? req.query.q.trim().substring(0, 100) : ''
      const page = toPositiveInt(req.query.page, 1)
      const pageSize = Math.min(toPositiveInt(req.query.pageSize, DEFAULT_PAGE_SIZE), MAX_PAGE_SIZE)

      const [rows]: any = await models.sequelize.query(
        `SELECT BasketItems.id, BasketItems.BasketId AS basketId, Products.id AS productId, Products.name, Products.price, BasketItems.quantity
         FROM BasketItems
         INNER JOIN Baskets ON Baskets.id = BasketItems.BasketId
         INNER JOIN Products ON Products.id = BasketItems.ProductId
         WHERE Baskets.UserId = :userId AND Products.name LIKE '%${q}%'
         ORDER BY BasketItems.id
         LIMIT :limit OFFSET :offset`,
        { replacements: { userId: user.data.id, limit: pageSize + 1, offset: (page - 1) * pageSize } }
      )

      res.json({
        status: 'success',
        page,
        pageSize,
        hasMore: rows.length > pageSize,
        data: rows
      })
    } catch (error) {
      next(error)
    }
  }
}
