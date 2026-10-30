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

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let otherAuthHeader: { Authorization: string, 'content-type': string }
let ownBasketId: number

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const { token } = await login(app, {
      email: 'jim@juice-sh.op',
      password: 'ncc-1701'
    })
    authHeader = {
      Authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    }

    const otherAuth = await login(app, {
      email: 'bender@juice-sh.op',
      password: 'OhG0dPlease1nsertLiquor!'
    })
    otherAuthHeader = {
      Authorization: 'Bearer ' + otherAuth.token,
      'content-type': 'application/json'
    }
    ownBasketId = otherAuth.bid
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
      .send({ BasketId: 2, ProductId: 1, quantity: 1 })
    assert.equal(res.status, 401)
  })

  void it('GET all basket items', async () => {
    const res = await request(app).get('/api/BasketItems').set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('POST new basket item', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 2, quantity: 1 })
    assert.equal(res.status, 200)
  })

  void it('POST new basket item with more than available quantity is forbidden', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 2, quantity: 101 })
    assert.equal(res.status, 400)
  })

  void it('POST new basket item with more than allowed quantity is forbidden', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 1, quantity: 6 })
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
      .send({ BasketId: 2, ProductId: 6, quantity: 3 })
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
      .send({ BasketId: 2, ProductId: 3, quantity: 3 })
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
      .send({ BasketId: 2, ProductId: 8, quantity: 8 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ BasketId: 42 })
    assert.equal(res.status, 400)
    assert.equal(res.body.message, 'null: `BasketId` cannot be updated due `noUpdate` constraint')
    assert.deepEqual(res.body.errors, [{ field: 'BasketId', message: '`BasketId` cannot be updated due `noUpdate` constraint' }])
  })

  void it('PUT update product ID of basket item is forbidden', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 9, quantity: 9 })
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
      .send({ BasketId: 2, ProductId: 12, quantity: 12 })
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
      .send({ BasketId: 2, ProductId: 1, quantity: 1 })
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
      .send({ BasketId: 2, ProductId: 10, quantity: 10 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .delete('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
    assert.equal(res.status, 200)
  })
})

void describe('/api/BasketItems ownership', () => {
  void it('POST ignores client-supplied BasketId of another user', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(otherAuthHeader)
      .send({ BasketId: 2, ProductId: 4, quantity: 1 })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.BasketId, ownBasketId)
  })

  void it('POST with duplicate BasketId keys still uses own basket', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(otherAuthHeader)
      .send(`{"ProductId":5,"BasketId":${ownBasketId},"quantity":1,"BasketId":2}`)
    assert.equal(res.status, 200)
    assert.equal(res.body.data.BasketId, ownBasketId)
  })

  void it('GET all basket items only returns items of own basket', async () => {
    const res = await request(app).get('/api/BasketItems').set(otherAuthHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 0)
    for (const item of res.body.data) {
      assert.equal(item.BasketId, ownBasketId)
    }
  })

  void it('GET basket item of another user is forbidden', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ ProductId: 7, quantity: 1 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .get('/api/BasketItems/' + createRes.body.data.id)
      .set(otherAuthHeader)
    assert.equal(res.status, 403)
  })

  void it('PUT update basket item of another user is forbidden', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ ProductId: 11, quantity: 1 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(otherAuthHeader)
      .send({ quantity: 2 })
    assert.equal(res.status, 403)

    const readRes = await request(app)
      .get('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
    assert.equal(readRes.body.data.quantity, 1)
  })

  void it('DELETE basket item of another user is forbidden', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ ProductId: 13, quantity: 1 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .delete('/api/BasketItems/' + createRes.body.data.id)
      .set(otherAuthHeader)
    assert.equal(res.status, 403)

    const readRes = await request(app)
      .get('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
    assert.equal(readRes.status, 200)
  })
})
