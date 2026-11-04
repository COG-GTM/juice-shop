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
import * as security from '../../lib/insecurity'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let bid: number

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const { token, bid: basketId } = await login(app, {
      email: 'jim@juice-sh.op',
      password: 'ncc-1701'
    })
    bid = basketId
    authHeader = {
      Authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    }
  },
  { timeout: 60000 }
)

void describe('/api/BasketItems', () => {
  void it('GET all basket items is forbidden via public API', async () => {
    const res = await request(app).get('/api/BasketItems')
    assert.equal(res.status, 401)
  })

  void it('POST new basket item is forbidden via public API', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .send({ BasketId: bid, ProductId: 1, quantity: 1 })
    assert.equal(res.status, 401)
  })

  void it('GET all basket items with valid token not cached in authenticated users', async () => {
    const token = security.authorize({ data: { id: security.decode(authHeader.Authorization.split(' ')[1]).data.id, email: 'jim@juice-sh.op' } })
    const res = await request(app)
      .get('/api/BasketItems')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 0)
    assert.ok(res.body.data.every((item: { BasketId: number }) => item.BasketId === bid))
  })

  void it('GET all basket items only returns items of own basket', async () => {
    const res = await request(app).get('/api/BasketItems').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 0)
    assert.ok(res.body.data.every((item: { BasketId: number }) => item.BasketId === bid))
  })

  void it('POST new basket item into basket of another user is forbidden', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: bid + 1, ProductId: 2, quantity: 1 })
    assert.equal(res.status, 401)
  })

  void it('POST new basket item into basket of another user via duplicate BasketId is forbidden', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send(`{ "ProductId": 14, "BasketId": "${bid}", "quantity": 1, "BasketId": "${bid + 1}" }`)
    assert.equal(res.status, 401)
  })

  void it('POST new basket item', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: bid, ProductId: 2, quantity: 1 })
    assert.equal(res.status, 200)
  })

  void it('POST new basket item with more than available quantity is forbidden', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: bid, ProductId: 2, quantity: 101 })
    assert.equal(res.status, 400)
  })

  void it('POST new basket item with more than allowed quantity is forbidden', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: bid, ProductId: 1, quantity: 6 })
    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'You can order only up to 5 items of this product.')
  })
})

void describe('/api/BasketItems/:id', () => {
  void it('GET basket item by id is forbidden via public API', async () => {
    const res = await request(app).get('/api/BasketItems/1')
    assert.equal(res.status, 401)
  })

  void it('PUT update basket item is forbidden via public API', async () => {
    const res = await request(app)
      .put('/api/BasketItems/1')
      .set({ 'content-type': 'application/json' })
      .send({ quantity: 2 })
    assert.equal(res.status, 401)
  })

  void it('DELETE basket item is forbidden via public API', async () => {
    const res = await request(app).delete('/api/BasketItems/1')
    assert.equal(res.status, 401)
  })

  void it('GET newly created basket item by id', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: bid, ProductId: 6, quantity: 3 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .get('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('PUT update newly created basket item', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: bid, ProductId: 3, quantity: 3 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ quantity: 20 })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.quantity, 20)
  })

  void it('PUT update basket ID of basket item is forbidden', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: bid, ProductId: 8, quantity: 8 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ BasketId: 42 })
    assert.equal(res.status, 400)
    assert.equal(res.body.message, 'null: `BasketId` cannot be updated due `noUpdate` constraint')
    assert.deepEqual(res.body.errors, [{ field: 'BasketId', message: '`BasketId` cannot be updated due `noUpdate` constraint' }])
  })

  void it('POST new basket item without basket ID is forbidden', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ ProductId: 8, quantity: 8 })
    assert.equal(res.status, 401)
  })

  void it('PUT update non-existing basket item is forbidden', async () => {
    const res = await request(app)
      .put('/api/BasketItems/4711')
      .set(authHeader)
      .send({ quantity: 1 })
    assert.equal(res.status, 403)
  })

  void it('PUT update product ID of basket item is forbidden', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: bid, ProductId: 9, quantity: 9 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ ProductId: 42 })
    assert.equal(res.status, 400)
    assert.equal(res.body.message, 'null: `ProductId` cannot be updated due `noUpdate` constraint')
    assert.deepEqual(res.body.errors, [{ field: 'ProductId', message: '`ProductId` cannot be updated due `noUpdate` constraint' }])
  })

  void it('PUT update newly created basket item with more than available quantity is forbidden', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: bid, ProductId: 12, quantity: 12 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ quantity: 100 })
    assert.equal(res.status, 400)
  })

  void it('PUT update basket item with more than allowed quantity is forbidden', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: bid, ProductId: 1, quantity: 1 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ quantity: 6 })
    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'You can order only up to 5 items of this product.')
  })

  void it('DELETE newly created basket item', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: bid, ProductId: 10, quantity: 10 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .delete('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
    assert.equal(res.status, 200)
  })
})

void describe('/api/BasketItems/:id of another user', () => {
  let foreignItemId: number

  before(async () => {
    const res = await request(app).get('/api/BasketItems').set(authHeader)
    const ownItemIds = res.body.data.map((item: { id: number }) => item.id)
    foreignItemId = [1, 2, 3, 4, 5].find(id => !ownItemIds.includes(id)) as number
  })

  void it('GET basket item of another user is forbidden', async () => {
    const res = await request(app).get('/api/BasketItems/' + foreignItemId).set(authHeader)
    assert.equal(res.status, 403)
  })

  void it('PUT update basket item of another user is forbidden', async () => {
    const res = await request(app)
      .put('/api/BasketItems/' + foreignItemId)
      .set(authHeader)
      .send({ quantity: 1 })
    assert.equal(res.status, 403)
  })

  void it('DELETE basket item of another user is forbidden', async () => {
    const res = await request(app).delete('/api/BasketItems/' + foreignItemId).set(authHeader)
    assert.equal(res.status, 403)
  })
})
