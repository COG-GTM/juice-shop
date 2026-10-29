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
let otherUserAuthHeader: { Authorization: string, 'content-type': string }

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

    const { token: otherUserToken } = await login(app, {
      email: 'admin@juice-sh.op',
      password: 'admin123'
    })
    otherUserAuthHeader = {
      Authorization: 'Bearer ' + otherUserToken,
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
      .send({ BasketId: 2, ProductId: 1, quantity: 1 })
    assert.equal(res.status, 401)
  })

  void it('GET all basket items only returns items of the caller\'s own basket', async () => {
    const res = await request(app).get('/api/BasketItems').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 0)
    for (const item of res.body.data) {
      assert.equal(item.BasketId, 2)
    }

    const otherRes = await request(app).get('/api/BasketItems').set(otherUserAuthHeader)
    assert.equal(otherRes.status, 200)
    assert.ok(otherRes.body.data.length > 0)
    for (const item of otherRes.body.data) {
      assert.equal(item.BasketId, 1)
    }
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

  void it('POST new basket item with own BasketId followed by duplicate foreign BasketId is forbidden', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send('{"ProductId":14,"quantity":1,"BasketId":2,"BasketId":1}')
    assert.equal(res.status, 401)

    const items = await request(app).get('/api/BasketItems').set(authHeader)
    assert.equal(items.body.data.some((item: { BasketId: number, ProductId: number }) => item.BasketId === 1 && item.ProductId === 14), false)
  })

  void it('POST new basket item with falsy first BasketId followed by foreign BasketId is forbidden', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send('{"ProductId":14,"quantity":1,"BasketId":0,"BasketId":1}')
    assert.equal(res.status, 401)
  })

  void it('POST new basket item with foreign BasketId followed by duplicate own BasketId is added to own basket', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send('{"ProductId":15,"quantity":1,"BasketId":1,"BasketId":2}')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.BasketId, 2)
  })

  void it('POST new basket item with BasketId hidden in nested object is added to own basket', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send('{"ProductId":16,"quantity":1,"x":{"BasketId":1}}')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.BasketId, 2)
  })

  void it('POST new basket item into basket of another user is forbidden', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 1, ProductId: 17, quantity: 1 })
    assert.equal(res.status, 401)
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

  void it('PUT update quantity of basket item via form-encoded body', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 14, quantity: 1 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set({ Authorization: authHeader.Authorization })
      .type('form')
      .send('quantity=2')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.quantity, 2)
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
    assert.equal(res.body.error, 'Only the quantity of a basket item can be updated.')
  })

  void it('POST new basket item without basket ID is added to own basket and cannot be moved', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ ProductId: 11, quantity: 1 })
    assert.equal(createRes.status, 200)
    assert.equal(createRes.body.data.BasketId, 2)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ BasketId: 3 })
    assert.equal(res.status, 400)
  })

  void it('PUT update quantity of basket item of another user is forbidden', async () => {
    const res = await request(app)
      .put('/api/BasketItems/1')
      .set(authHeader)
      .send({ quantity: 5 })
    assert.equal(res.status, 403)
  })

  void it('PUT move basket item of another user is forbidden', async () => {
    const res = await request(app)
      .put('/api/BasketItems/1')
      .set(authHeader)
      .send({ BasketId: 2 })
    assert.equal(res.status, 403)
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
      .send({ BasketId: 2, ProductId: 9, quantity: 9 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ ProductId: 42 })
    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'Only the quantity of a basket item can be updated.')
  })

  void it('PUT update quantity together with product ID of basket item is forbidden', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 11, quantity: 1 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ quantity: 2, ProductId: 1 })
    assert.equal(res.status, 400)

    const getRes = await request(app)
      .get('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
    assert.equal(getRes.status, 200)
    assert.equal(getRes.body.data.ProductId, 11)
    assert.equal(getRes.body.data.quantity, 1)
  })

  void it('PUT update basket item of another user is forbidden and leaves it unchanged', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 5, quantity: 1 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(otherUserAuthHeader)
      .send({ quantity: 5 })
    assert.equal(res.status, 403)

    const getRes = await request(app)
      .get('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
    assert.equal(getRes.status, 200)
    assert.equal(getRes.body.data.quantity, 1)
    assert.equal(getRes.body.data.BasketId, 2)
  })

  void it('GET basket item of another user is forbidden', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 7, quantity: 1 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .get('/api/BasketItems/' + createRes.body.data.id)
      .set(otherUserAuthHeader)
    assert.equal(res.status, 403)
  })

  void it('DELETE basket item of another user is forbidden and leaves it in place', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 13, quantity: 1 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .delete('/api/BasketItems/' + createRes.body.data.id)
      .set(otherUserAuthHeader)
    assert.equal(res.status, 403)

    const getRes = await request(app)
      .get('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
    assert.equal(getRes.status, 200)
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
