/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'

interface Caller {
  id?: number
  isAdmin: boolean
}

interface FetchContext {
  instance: any
  error: (status: number, message: string) => any
  continue: any
}

export function callerFrom (req: Request): Caller {
  const user = security.authenticatedUsers.from(req)?.data
  const id = user?.id
  return {
    id: typeof id === 'number' ? id : undefined,
    isAdmin: user?.role === security.roles.admin
  }
}

async function basketIdsOf (userId: number) {
  const baskets = await BasketModel.findAll({ where: { UserId: userId }, attributes: ['id'] })
  return new Set(baskets.map(({ id }) => id))
}

function guardInstances (resource: any, actions: string[], mayAccess: (caller: Caller, instance: any, req: Request) => Promise<boolean> | boolean) {
  for (const action of actions) {
    resource[action].fetch.after(async (req: Request, res: Response, context: FetchContext) => {
      const caller = callerFrom(req)
      if (caller.isAdmin || (caller.id !== undefined && await mayAccess(caller, context.instance, req))) {
        return context.continue
      }
      return context.error(403, 'Forbidden')
    })
  }
}

function filterList (resource: any, ownedBy: (caller: Caller) => Promise<(instance: any) => boolean> | ((instance: any) => boolean)) {
  resource.list.fetch.after(async (req: Request, res: Response, context: FetchContext) => {
    const caller = callerFrom(req)
    if (!caller.isAdmin) {
      const isOwned = caller.id === undefined ? () => false : await ownedBy(caller)
      context.instance = context.instance.filter(isOwned)
    }
    return context.continue
  })
}

export function enforceResourceOwnership (name: string, resource: any) {
  switch (name) {
    case 'BasketItem':
      filterList(resource, async (caller) => {
        const basketIds = await basketIdsOf(caller.id as number)
        return (item) => basketIds.has(item.BasketId)
      })
      guardInstances(resource, ['read', 'delete'], async (caller, item) => (await basketIdsOf(caller.id as number)).has(item.BasketId))
      guardInstances(resource, ['update'], async (caller, item, req) => (await basketIdsOf(caller.id as number)).has(item.BasketId ?? Number(req.body.BasketId)))
      break
    case 'Complaint':
      filterList(resource, (caller) => (complaint) => complaint.UserId === caller.id)
      break
    case 'Feedback':
      guardInstances(resource, ['read', 'update', 'delete'], (caller, feedback) => feedback.UserId === caller.id)
      break
  }
}
