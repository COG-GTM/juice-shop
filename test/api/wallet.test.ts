/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { CardModel } from '../../models/card'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token } = await login(app, { email: 'demo', password: 'demo' })
  authHeader = { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
}, { timeout: 60000 })

async function getBalance (): Promise<number> {
  const res = await request(app).get('/rest/wallet/balance').set(authHeader)
  assert.equal(res.status, 200)
  return res.body.data
}

async function assertTopUpRejected (body: Record<string, unknown>, status: number) {
  const before = await getBalance()
  const res = await request(app)
    .put('/rest/wallet/balance')
    .set(authHeader)
    .send(body)
  assert.equal(res.status, status)
  assert.equal(await getBalance(), before)
}

void describe('/api/Wallets', () => {
  void it('GET wallet is forbidden via public API', async () => {
    const res = await request(app)
      .get('/rest/wallet/balance')
    assert.equal(res.status, 401)
  })

  void it('GET wallet retrieves wallet amount of requesting user', async () => {
    const res = await request(app)
      .get('/rest/wallet/balance')
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data, 200)
  })

  void it('PUT wallet is forbidden via public API', async () => {
    const res = await request(app)
      .put('/rest/wallet/balance')
      .send({ balance: 10 })
    assert.equal(res.status, 401)
  })

  void it('PUT charge wallet from credit card of requesting user', async () => {
    const res = await request(app)
      .put('/rest/wallet/balance')
      .set(authHeader)
      .send({ balance: 10, paymentId: 2 })
    assert.equal(res.status, 200)

    const balanceRes = await request(app)
      .get('/rest/wallet/balance')
      .set(authHeader)
    assert.equal(balanceRes.status, 200)
    assert.ok(balanceRes.headers['content-type']?.includes('application/json'))
    assert.equal(balanceRes.body.data, 210)
  })

  void it('PUT charge wallet with numeric-string amount credits the parsed number', async () => {
    const before = await getBalance()
    const res = await request(app)
      .put('/rest/wallet/balance')
      .set(authHeader)
      .send({ balance: '10', paymentId: 2 })
    assert.equal(res.status, 200)
    assert.equal(res.body.data, 10)
    const after = await getBalance()
    assert.equal(typeof after, 'number')
    assert.equal(after, before + 10)
  })

  void it('PUT charge wallet accepts the minimum and maximum amounts', async () => {
    for (const amount of [10, 1000]) {
      const before = await getBalance()
      const res = await request(app)
        .put('/rest/wallet/balance')
        .set(authHeader)
        .send({ balance: amount, paymentId: 2 })
      assert.equal(res.status, 200)
      assert.equal(await getBalance(), before + amount)
    }
  })

  void it('PUT charge wallet just outside the amount limits is rejected', async () => {
    for (const balance of [9, 1001]) {
      await assertTopUpRejected({ balance, paymentId: 2 }, 400)
    }
  })

  void it('PUT charge wallet with negative amount is rejected', async () => {
    await assertTopUpRejected({ balance: -500, paymentId: 2 }, 400)
  })

  void it('PUT charge wallet with zero amount is rejected', async () => {
    await assertTopUpRejected({ balance: 0, paymentId: 2 }, 400)
  })

  void it('PUT charge wallet with amount above maximum is rejected', async () => {
    await assertTopUpRejected({ balance: 999999, paymentId: 2 }, 400)
  })

  void it('PUT charge wallet with non-numeric amount is rejected', async () => {
    await assertTopUpRejected({ balance: 'lots', paymentId: 2 }, 400)
  })

  void it('PUT charge wallet with non-integer amount is rejected', async () => {
    await assertTopUpRejected({ balance: 10.5, paymentId: 2 }, 400)
  })

  void it('PUT charge wallet rejects free-credit amounts without crediting the wallet', async () => {
    for (const balance of [-5, 1.5, 'abc', 1000000000000, 1000000]) {
      await assertTopUpRejected({ balance, paymentId: 2 }, 400)
    }
  })

  void it('PUT charge wallet from foreign credit card is forbidden', async () => {
    await assertTopUpRejected({ balance: 10, paymentId: 1 }, 402)
  })

  void it('PUT charge wallet with malformed card id is forbidden', async () => {
    for (const paymentId of [[2], true, '2abc']) {
      await assertTopUpRejected({ balance: 10, paymentId }, 402)
    }
  })

  void it('PUT charge wallet without credit card is forbidden', async () => {
    await assertTopUpRejected({ balance: 10 }, 402)
  })

  void it('PUT charge wallet from expired credit card is rejected', async () => {
    const card = await CardModel.findByPk(2)
    assert.ok(card)
    const { expMonth, expYear } = card
    const now = new Date()
    const lastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1)
    try {
      await CardModel.update({ expMonth: lastMonth.getMonth() + 1, expYear: lastMonth.getFullYear() }, { where: { id: 2 }, validate: false })
      await assertTopUpRejected({ balance: 10, paymentId: 2 }, 402)
    } finally {
      await CardModel.update({ expMonth, expYear }, { where: { id: 2 } })
    }
  })

  void it('PUT charge wallet from credit card expiring this month is accepted', async () => {
    const card = await CardModel.findByPk(2)
    assert.ok(card)
    const { expMonth, expYear } = card
    const now = new Date()
    try {
      await CardModel.update({ expMonth: now.getMonth() + 1, expYear: now.getFullYear() }, { where: { id: 2 }, validate: false })
      const balanceBefore = await request(app).get('/rest/wallet/balance').set(authHeader)

      const res = await request(app)
        .put('/rest/wallet/balance')
        .set(authHeader)
        .send({ balance: 10, paymentId: 2 })
      assert.equal(res.status, 200)

      const balanceAfter = await request(app).get('/rest/wallet/balance').set(authHeader)
      assert.equal(balanceAfter.body.data, balanceBefore.body.data + 10)
    } finally {
      await CardModel.update({ expMonth, expYear }, { where: { id: 2 } })
    }
  })
})
