/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

interface AttributeDefinition { type?: { key?: string } }

const SEARCHABLE_TYPES = ['STRING', 'TEXT', 'CITEXT']

// finale searches, sorts and filters on every raw attribute by default, so attributes hidden via
// excludeAttributes could still be probed through ?q=, ?sort= or ?<attribute>= on list requests
export function restrictQueryableAttributes (resource: any, rawAttributes: Record<string, AttributeDefinition>, excluded: string[]) {
  const queryable = Object.keys(rawAttributes).filter(attribute => !excluded.includes(attribute))
  resource.search = {
    param: 'q',
    attributes: queryable.filter(attribute => SEARCHABLE_TYPES.includes(rawAttributes[attribute].type?.key ?? ''))
  }
  resource.sort = { param: 'sort', attributes: queryable }
  resource.list.fetch.before((req: Request, res: Response, context: { continue: any }) => {
    for (const attribute of excluded) {
      delete req.query[attribute]
    }
    return context.continue
  })
}
