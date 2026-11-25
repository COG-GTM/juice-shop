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
import { createDiscountCode } from '../../routes/basketDiscount'

let app: Express
let customerHeader: { Authorization: string, 'content-type': string }
let accountingHeader: { Authorization: string, 'content-type': string }

const inOneWeek = () => Date.now() + 7 * 24 * 60 * 60 * 1000

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const customer = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    customerHeader = { Authorization: 'Bearer ' + customer.token, 'content-type': 'application/json' }

    const accountant = await login(app, { email: 'accountant@juice-sh.op', password: 'i am an awesome accountant' })
    accountingHeader = { Authorization: 'Bearer ' + accountant.token, 'content-type': 'application/json' }
  },
  { timeout: 60000 }
)

void describe('/rest/discounts', () => {
  void it('POST issues a discount code for accounting users', async () => {
    const res = await request(app).post('/rest/discounts').set(accountingHeader).send({ percent: 15 })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.percent, 15)
    assert.ok(typeof res.body.data.code === 'string')
  })

  void it('POST is forbidden for customers', async () => {
    const res = await request(app).post('/rest/discounts').set(customerHeader).send({ percent: 15 })
    assert.equal(res.status, 403)
  })

  void it('POST rejects discounts above the allowed maximum', async () => {
    const res = await request(app).post('/rest/discounts').set(accountingHeader).send({ percent: 75 })
    assert.equal(res.status, 400)
  })
})

void describe('/rest/basket/:id/discount', () => {
  void it('PUT is not allowed without authentication', async () => {
    const res = await request(app).put('/rest/basket/2/discount').send({ code: createDiscountCode(10, inOneWeek()) })
    assert.equal(res.status, 401)
  })

  void it('PUT applies a valid discount code to the basket', async () => {
    const res = await request(app).put('/rest/basket/2/discount').set(customerHeader).send({ code: createDiscountCode(10, inOneWeek()) })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.discount, 10)
  })

  void it('PUT rejects an expired discount code', async () => {
    const res = await request(app).put('/rest/basket/2/discount').set(customerHeader).send({ code: createDiscountCode(10, Date.now() - 1000) })
    assert.equal(res.status, 400)
  })

  void it('PUT rejects a tampered discount code', async () => {
    const [, expiresAt, signature] = Buffer.from(createDiscountCode(10, inOneWeek()), 'base64url').toString().split('.')
    const tampered = Buffer.from(`40.${expiresAt}.${signature}`).toString('base64url')
    const res = await request(app).put('/rest/basket/2/discount').set(customerHeader).send({ code: tampered })
    assert.equal(res.status, 400)
  })

  void it('PUT returns 404 for a non-existing basket', async () => {
    const res = await request(app).put('/rest/basket/4711/discount').set(customerHeader).send({ code: createDiscountCode(10, inOneWeek()) })
    assert.equal(res.status, 404)
  })
})
