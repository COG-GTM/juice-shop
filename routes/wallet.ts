/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { WalletModel } from '../models/wallet'
import { CardModel } from '../models/card'

const MIN_TOP_UP_AMOUNT = 10
const MAX_TOP_UP_AMOUNT = 1000

function parseTopUpAmount (value: unknown): number | null {
  const amount = typeof value === 'number' ? value : (typeof value === 'string' && value.trim() !== '' ? Number(value) : NaN)
  if (!Number.isInteger(amount) || amount < MIN_TOP_UP_AMOUNT || amount > MAX_TOP_UP_AMOUNT) {
    return null
  }
  return amount
}

function isCardExpired (card: CardModel): boolean {
  const now = new Date()
  const year = now.getFullYear()
  const month = now.getMonth() + 1
  return card.expYear < year || (card.expYear === year && card.expMonth < month)
}

export function getWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId } })
    if (wallet != null) {
      res.status(200).json({ status: 'success', data: wallet.balance })
    } else {
      res.status(404).json({ status: 'error' })
    }
  }
}

export function addWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const amount = parseTopUpAmount(req.body.balance)
    if (amount === null) {
      res.status(400).json({ status: 'error', message: `Top-up amount must be a whole number between ${MIN_TOP_UP_AMOUNT} and ${MAX_TOP_UP_AMOUNT}.` })
      return
    }
    const cardId = Number(req.body.paymentId)
    const card = Number.isInteger(cardId) && cardId > 0 ? await CardModel.findOne({ where: { id: cardId, UserId: req.body.UserId } }) : null
    if (card != null && !isCardExpired(card)) {
      try {
        await WalletModel.increment({ balance: amount }, { where: { UserId: req.body.UserId } })
        res.status(200).json({ status: 'success', data: amount })
      } catch {
        res.status(404).json({ status: 'error' })
      }
    } else {
      res.status(402).json({ status: 'error', message: 'Payment not accepted.' })
    }
  }
}
