/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import fs from 'node:fs'
import crypto from 'node:crypto'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/order-history', () => {
  void it('GET own previous orders', async () => {
    const { token } = await login(app, {
      email: 'admin@' + config.get<string>('application.domain'),
      password: 'admin123'
    })

    const res = await request(app)
      .get('/rest/order-history')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

    assert.equal(res.status, 200)
    assert.equal(res.body.data[0].totalPrice, 8.96)
    assert.equal(res.body.data[0].delivered, false)
    assert.equal(res.body.data[0].products[0].quantity, 3)
    assert.equal(res.body.data[0].products[0].name, 'Apple Juice (1000ml)')
    assert.equal(res.body.data[0].products[0].price, 1.99)
    assert.equal(res.body.data[0].products[0].total, 5.97)
    assert.equal(res.body.data[0].products[1].quantity, 1)
    assert.equal(res.body.data[0].products[1].name, 'Orange Juice (1000ml)')
    assert.equal(res.body.data[0].products[1].price, 2.99)
    assert.equal(res.body.data[0].products[1].total, 2.99)
    assert.equal(res.body.data[1].totalPrice, 26.97)
    assert.equal(res.body.data[1].delivered, true)
    assert.equal(res.body.data[1].products[0].quantity, 3)
    assert.equal(res.body.data[1].products[0].name, 'Eggfruit Juice (500ml)')
    assert.equal(res.body.data[1].products[0].price, 8.99)
    assert.equal(res.body.data[1].products[0].total, 26.97)
  })
})

void describe('/rest/order-history/orders', () => {
  void it('GET all orders is forbidden for customers', async () => {
    const { token } = await login(app, {
      email: 'jim@' + config.get<string>('application.domain'),
      password: 'ncc-1701'
    })

    const res = await request(app)
      .get('/rest/order-history/orders')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

    assert.equal(res.status, 403)
  })

  void it('GET all orders is forbidden for admin', async () => {
    const { token } = await login(app, {
      email: 'admin@' + config.get<string>('application.domain'),
      password: 'admin123'
    })

    const res = await request(app)
      .get('/rest/order-history/orders')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

    assert.equal(res.status, 403)
  })

  void it('GET all orders for accountant', async () => {
    const { token } = await login(app, {
      email: 'accountant@' + config.get<string>('application.domain'),
      password: 'i am an awesome accountant'
    })

    const res = await request(app)
      .get('/rest/order-history/orders')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

    assert.equal(res.status, 200)
  })
})

void describe('/rest/order-history/:id/delivery-status', () => {
  void it('PUT delivery status is forbidden for admin', async () => {
    const { token } = await login(app, {
      email: 'admin@' + config.get<string>('application.domain'),
      password: 'admin123'
    })

    const res = await request(app)
      .put('/rest/order-history/1/delivery-status')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({ delivered: false })

    assert.equal(res.status, 403)
  })

  void it('PUT delivery status is forbidden for customer', async () => {
    const { token } = await login(app, {
      email: 'jim@' + config.get<string>('application.domain'),
      password: 'ncc-1701'
    })

    const res = await request(app)
      .put('/rest/order-history/1/delivery-status')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({ delivered: false })

    assert.equal(res.status, 403)
  })

  void it('PUT delivery status is allowed for accountant', async () => {
    const { token } = await login(app, {
      email: 'accountant@' + config.get<string>('application.domain'),
      password: 'i am an awesome accountant'
    })

    const res = await request(app)
      .put('/rest/order-history/1/delivery-status')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({ delivered: false })

    assert.equal(res.status, 200)
  })
})

void describe('forged accounting JWTs', () => {
  const b64url = (obj: object) => Buffer.from(JSON.stringify(obj)).toString('base64url')
  const payload = b64url({ data: { id: 1, email: 'mallory@juice-sh.op', role: 'accounting' }, iat: 1508639612, exp: 9999999999 })
  const unsignedToken = `${b64url({ alg: 'none', typ: 'JWT' })}.${payload}.`
  const hsInput = `${b64url({ alg: 'HS256', typ: 'JWT' })}.${payload}`
  const hsSignature = crypto.createHmac('sha256', fs.readFileSync('encryptionkeys/jwt.pub', 'utf8')).update(hsInput).digest('base64url')
  const hsToken = `${hsInput}.${hsSignature}`

  for (const [name, token] of [['alg none', unsignedToken], ['HS256 signed with public key', hsToken]]) {
    void it(`GET all orders rejects ${name} token`, async () => {
      const res = await request(app)
        .get('/rest/order-history/orders')
        .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      assert.equal(res.status, 403)
    })

    void it(`PUT delivery status rejects ${name} token`, async () => {
      const res = await request(app)
        .put('/rest/order-history/1/delivery-status')
        .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
        .send({ delivered: false })
      assert.equal(res.status, 403)
    })

    void it(`protected route rejects ${name} token`, async () => {
      const res = await request(app)
        .get('/api/Cards')
        .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      assert.equal(res.status, 401)
    })

    void it(`whoami does not register ${name} token as a session`, async () => {
      const res = await request(app)
        .get('/rest/user/whoami')
        .set({ Authorization: 'Bearer ' + token, Cookie: 'token=' + token })
      assert.equal(res.status, 200)
      assert.equal(res.body.user.id, undefined)

      const cards = await request(app)
        .get('/api/Cards')
        .set({ Authorization: 'Bearer ' + token, Cookie: 'token=' + token })
      assert.equal(cards.status, 401)
    })
  }
})
