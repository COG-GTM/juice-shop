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

const MIN_TOP_UP = 10
const MAX_TOP_UP = 1000

function isValidTopUpAmount (amount: unknown): amount is number {
  return typeof amount === 'number' && Number.isFinite(amount) && amount >= MIN_TOP_UP && amount <= MAX_TOP_UP
}

function isCardExpired (card: { expMonth: number, expYear: number }) {
  const now = new Date()
  return card.expYear < now.getFullYear() || (card.expYear === now.getFullYear() && card.expMonth < now.getMonth() + 1)
}

export function addWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const amount = req.body.balance
    if (!isValidTopUpAmount(amount)) {
      res.status(400).json({ status: 'error', message: `Amount must be a number between ${MIN_TOP_UP} and ${MAX_TOP_UP}.` })
      return
    }
    const cardId = req.body.paymentId
    const card = cardId ? await CardModel.findOne({ where: { id: cardId, UserId: req.body.UserId } }) : null
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
