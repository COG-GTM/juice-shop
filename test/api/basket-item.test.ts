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
import { BasketItemModel } from '../../models/basketitem'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }

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

  void it('POST new basket item into another user\'s basket is forbidden', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 1, ProductId: 2, quantity: 1 })
    assert.equal(res.status, 401)
  })

  void it('POST new basket item with duplicate BasketId keys is rejected', async () => {
    const before = await BasketItemModel.count({ where: { BasketId: 1 } })
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send('{ "ProductId": 14, "BasketId": "2", "quantity": 1, "BasketId": "1" }')
    assert.equal(res.status, 400)
    assert.equal(await BasketItemModel.count({ where: { BasketId: 1 } }), before)
  })

  void it('POST new basket item with duplicate quantity keys is rejected', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send('{ "ProductId": 14, "BasketId": "2", "quantity": 1, "quantity": -5 }')
    assert.equal(res.status, 400)
  })

  for (const quantity of [-5, 0, 1.5, '1']) {
    void it(`POST new basket item with quantity ${JSON.stringify(quantity)} is rejected`, async () => {
      const res = await request(app)
        .post('/api/BasketItems')
        .set(authHeader)
        .send({ BasketId: 2, ProductId: 5, quantity })
      assert.equal(res.status, 400)
    })
  }
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

  void it('POST basket item without basket ID is stored in the session basket and cannot be moved', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ ProductId: 13, quantity: 8 })
    assert.equal(createRes.status, 200)
    assert.equal(createRes.body.data.BasketId, 2)

    const res = await request(app)
      .put('/api/BasketItems/' + createRes.body.data.id)
      .set(authHeader)
      .send({ BasketId: 3 })
    assert.equal(res.status, 400)
  })

  void it('PUT update basket item of another user is forbidden', async () => {
    const res = await request(app)
      .put('/api/BasketItems/1')
      .set(authHeader)
      .send({ quantity: 1 })
    assert.equal(res.status, 403)
    const item = await BasketItemModel.findByPk(1)
    assert.equal(item?.quantity, 2)
  })

  void it('PUT update non-existent basket item returns 404', async () => {
    const res = await request(app)
      .put('/api/BasketItems/999999')
      .set(authHeader)
      .send({ quantity: 1 })
    assert.equal(res.status, 404)
  })

  for (const [ProductId, quantity] of [[15, -100000], [16, 0], [17, 2.5]]) {
    void it(`PUT update basket item to quantity ${quantity} is rejected`, async () => {
      const createRes = await request(app)
        .post('/api/BasketItems')
        .set(authHeader)
        .send({ BasketId: 2, ProductId, quantity: 1 })
      assert.equal(createRes.status, 200)

      const res = await request(app)
        .put('/api/BasketItems/' + createRes.body.data.id)
        .set(authHeader)
        .send({ quantity })
      assert.equal(res.status, 400)
    })
  }

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

  void it('DELETE basket item of another user is forbidden', async () => {
    const res = await request(app)
      .delete('/api/BasketItems/1')
      .set(authHeader)
    assert.equal(res.status, 403)

    const item = await BasketItemModel.findOne({ where: { id: 1 } })
    assert.ok(item !== null)
  })

  void it('DELETE non-existing basket item returns 404', async () => {
    const res = await request(app)
      .delete('/api/BasketItems/999999')
      .set(authHeader)
    assert.equal(res.status, 404)
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

  void it('DELETE own basket item without body or content type', async () => {
    const createRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 11, quantity: 1 })
    assert.equal(createRes.status, 200)

    const res = await request(app)
      .delete('/api/BasketItems/' + createRes.body.data.id)
      .set({ Authorization: authHeader.Authorization })
    assert.equal(res.status, 200)
  })
})
