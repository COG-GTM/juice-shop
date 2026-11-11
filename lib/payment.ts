/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Op, literal, type Transaction } from 'sequelize'
import { CardModel } from '../models/card'
import { WalletModel } from '../models/wallet'

export const walletTopUpLimits = { min: 10, max: 1000 }

export class PaymentError extends Error {
  constructor (message: string, public readonly reason: 'invalidAmount' | 'invalidCard' | 'insufficientFunds') {
    super(message)
    this.name = 'PaymentError'
  }
}

function assertValidAmount (amount: unknown): asserts amount is number {
  if (typeof amount !== 'number' || !Number.isFinite(amount) || amount < 0) {
    throw new PaymentError('Invalid payment amount.', 'invalidAmount')
  }
}

function toId (value: unknown) {
  if (typeof value === 'number') return value
  if (typeof value === 'string' && /^\d+$/.test(value)) return Number(value)
  return NaN
}

function isExpired (card: CardModel) {
  const now = new Date()
  return card.expYear < now.getFullYear() || (card.expYear === now.getFullYear() && card.expMonth - 1 < now.getMonth())
}

export async function findValidCard (cardId: unknown, userId: unknown) {
  const id = toId(cardId)
  const UserId = toId(userId)
  if (!Number.isSafeInteger(id) || !Number.isSafeInteger(UserId)) return null
  const card = await CardModel.findOne({ where: { id, UserId } })
  return card != null && !isExpired(card) ? card : null
}

// No external payment provider is integrated, so a valid, unexpired card owned by the payer counts as a successful charge.
export async function chargeCard (userId: unknown, cardId: unknown, amount: unknown) {
  assertValidAmount(amount)
  const card = await findValidCard(cardId, userId)
  if (card == null) {
    throw new PaymentError('Invalid Card', 'invalidCard')
  }
  return card
}

export async function debitWallet (userId: unknown, amount: unknown, transaction?: Transaction) {
  assertValidAmount(amount)
  const UserId = toId(userId)
  if (!Number.isSafeInteger(UserId)) {
    throw new PaymentError('Insufficient wallet balance.', 'insufficientFunds')
  }
  const [affectedRows] = await WalletModel.update(
    { balance: literal(`balance - ${amount}`) },
    { where: { UserId, balance: { [Op.gte]: amount } }, transaction }
  )
  if (affectedRows < 1) {
    throw new PaymentError('Insufficient wallet balance.', 'insufficientFunds')
  }
}

export async function processPayment (userId: unknown, paymentId: unknown, amount: unknown, transaction?: Transaction) {
  if (paymentId === 'wallet') {
    await debitWallet(userId, amount, transaction)
  } else {
    await chargeCard(userId, paymentId, amount)
  }
}
