/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

// Finale list endpoints turn query params named like model attributes into WHERE filters,
// apply `q` as a LIKE search over every string attribute and allow `sort` on any attribute,
// all regardless of `excludeAttributes`, so excluded columns must be removed from the query.
export function stripExcludedAttributeQuery (excluded: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const query = req.query as Record<string, unknown>
    for (const attribute of excluded) {
      delete query[attribute]
    }
    delete query.q
    if (query.sort !== undefined) {
      const columns = (Array.isArray(query.sort) ? query.sort : [query.sort])
        .flatMap(sort => typeof sort === 'string' ? sort.split(',') : [])
        .filter(column => column !== '' && !excluded.includes(column.replace(/^-/, '')))
      if (columns.length > 0) {
        query.sort = columns.join(',')
      } else {
        delete query.sort
      }
    }
    next()
  }
}
