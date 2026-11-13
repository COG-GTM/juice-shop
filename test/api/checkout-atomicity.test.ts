/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { BasketItemModel } from '../../models/basketitem'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import { UserModel } from '../../models/user'
import { WalletModel } from '../../models/wallet'

let app: Express
let ProductId: number
let price: number

before(async () => {
  const result = await createTestApp()
  app = result.app
  const product = (await ProductModel.findAll({ order: [['id', 'ASC']] })).find(({ price }) => Number.isInteger(price) && price >= 10)!
  ProductId = product.id
  price = product.price
}, { timeout: 60000 })

async function customerWithBasket (email: string, quantity: number) {
  await register(app, { email, password: 'checkout-race' })
  const { token, bid } = await login(app, { email, password: 'checkout-race' })
  const user = await UserModel.findOne({ where: { email } })
  await BasketItemModel.create({ BasketId: bid, ProductId, quantity })
  return {
    UserId: user!.id,
    bid,
    authHeader: { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
  }
}

async function stock () {
  return (await QuantityModel.findOne({ where: { ProductId } }))!.quantity
}

async function balance (UserId: number) {
  return (await WalletModel.findOne({ where: { UserId } }))!.balance
}

function checkout (bid: number, authHeader: Record<string, string>) {
  return request(app).post(`/rest/basket/${bid}/checkout`).set(authHeader).send({ orderDetails: { paymentId: 'wallet' } })
}

void describe('/rest/basket/:id/checkout stock and wallet consistency', () => {
  void it('leaves stock unchanged when the wallet cannot pay', async () => {
    const { UserId, bid, authHeader } = await customerWithBasket('checkout-empty-wallet@juice-sh.op', 2)
    await WalletModel.update({ balance: 0 }, { where: { UserId } })
    await QuantityModel.update({ quantity: 50 }, { where: { ProductId } })

    for (let i = 0; i < 3; i++) {
      const res = await checkout(bid, authHeader)
      assert.equal(res.status, 500)
      assert.ok(res.text.includes('Insufficient wallet balance.'))
    }

    assert.equal(await stock(), 50)
    assert.equal(await balance(UserId), 0)
    assert.equal(await BasketItemModel.count({ where: { BasketId: bid } }), 1)
  })

  void it('accepts only the affordable order when checkouts run in parallel', async () => {
    const { UserId, bid, authHeader } = await customerWithBasket('checkout-parallel@juice-sh.op', 1)
    await WalletModel.update({ balance: price }, { where: { UserId } })
    await QuantityModel.update({ quantity: 50 }, { where: { ProductId } })

    const responses = await Promise.all(Array.from({ length: 5 }, async () => await checkout(bid, authHeader)))

    assert.equal(responses.filter(res => res.status === 200).length, 1)
    assert.equal(await balance(UserId), Math.round(price / 10))
    assert.equal(await stock(), 49)
  })

  void it('refuses checkout without touching stock or wallet when stock would go below zero', async () => {
    const { UserId, bid, authHeader } = await customerWithBasket('checkout-low-stock@juice-sh.op', 3)
    await WalletModel.update({ balance: price * 10 }, { where: { UserId } })
    await QuantityModel.update({ quantity: 2 }, { where: { ProductId } })

    const res = await checkout(bid, authHeader)

    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'We are out of stock! Sorry for the inconvenience.')
    assert.equal(await stock(), 2)
    assert.equal(await balance(UserId), price * 10)
  })
})
