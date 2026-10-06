/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { WalletModel } from '../models/wallet'
import { CardModel } from '../models/card'

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

const MIN_TOP_UP_AMOUNT = 10
const MAX_TOP_UP_AMOUNT = 1000

function parseTopUpAmount (value: unknown): number | null {
  const amount = typeof value === 'number' ? value : (typeof value === 'string' && value.trim() !== '' ? Number(value) : NaN)
  if (!Number.isFinite(amount) || amount < MIN_TOP_UP_AMOUNT || amount > MAX_TOP_UP_AMOUNT) return null
  if (Number(amount.toFixed(2)) !== amount) return null
  return amount
}

function parsePaymentId (value: unknown): number | null {
  if (typeof value === 'number') return Number.isSafeInteger(value) && value > 0 ? value : null
  if (typeof value === 'string' && /^[1-9]\d{0,15}$/.test(value)) return Number(value)
  return null
}

export function addWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const amount = parseTopUpAmount(req.body.balance)
    if (amount === null) {
      res.status(400).json({ status: 'error', message: `Amount must be between ${MIN_TOP_UP_AMOUNT} and ${MAX_TOP_UP_AMOUNT} with at most two decimal places.` })
      return
    }
    const cardId = parsePaymentId(req.body.paymentId)
    const card = cardId !== null ? await CardModel.findOne({ where: { id: cardId, UserId: req.body.UserId } }) : null
    if (card != null) {
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
