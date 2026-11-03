import { type Request } from 'express'
import { type FindOptions } from 'sequelize'
import { BasketModel } from '../models/basket'
import * as security from './insecurity'

export async function findOwnBasket (req: Request, basketId: unknown, options: Omit<FindOptions, 'where'> = {}): Promise<BasketModel | null> {
  const userId = security.authenticatedUsers.from(req)?.data?.id
  const id = Number(basketId)
  if (userId == null || !Number.isInteger(id)) return null
  return await BasketModel.findOne({ ...options, where: { id, UserId: userId } })
}

export async function ownBasketIds (req: Request): Promise<number[]> {
  const userId = security.authenticatedUsers.from(req)?.data?.id
  if (userId == null) return []
  const baskets = await BasketModel.findAll({ where: { UserId: userId } })
  return baskets.map(basket => basket.id)
}
