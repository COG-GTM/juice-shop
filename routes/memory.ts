/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { MemoryModel } from '../models/memory'
import { UserModel } from '../models/user'

export function addMemory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const record = {
      caption: req.body.caption,
      imagePath: 'assets/public/images/uploads/' + req.file?.filename,
      UserId: req.body.UserId
    }
    const memory = await MemoryModel.create(record)
    res.status(200).json({ status: 'success', data: memory })
  }
}

export const DEFAULT_MEMORIES_PAGE_SIZE = 24
export const MAX_MEMORIES_PAGE_SIZE = 100

function parseNonNegativeInt (value: unknown): number | undefined {
  if (typeof value !== 'string' || !/^\d{1,9}$/.test(value)) return undefined
  return Number.parseInt(value, 10)
}

export function getMemories () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const requestedLimit = parseNonNegativeInt(req.query.limit)
    const limit = requestedLimit === undefined || requestedLimit < 1
      ? DEFAULT_MEMORIES_PAGE_SIZE
      : Math.min(requestedLimit, MAX_MEMORIES_PAGE_SIZE)
    const offset = parseNonNegativeInt(req.query.offset) ?? 0

    const { count, rows } = await MemoryModel.findAndCountAll({
      include: [{ model: UserModel, attributes: ['id', 'username'] }],
      order: [['createdAt', 'DESC'], ['id', 'DESC']],
      limit,
      offset
    })
    res.status(200).json({ status: 'success', data: rows, meta: { total: count, limit, offset } })
  }
}
