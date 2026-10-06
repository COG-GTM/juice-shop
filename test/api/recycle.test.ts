/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'
import { login } from './helpers/auth'

let app: Express
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }
let userAuthHeader: { Authorization: string, 'content-type': string }
let userId: number

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token } = await login(app, { email: 'demo', password: 'demo' })
  userAuthHeader = { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
  userId = security.decode(token).data.id
}, { timeout: 60000 })

void describe('/api/Recycles', () => {
  void it('POST new recycle', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set(authHeader)
      .send({
        quantity: 200,
        AddressId: '1',
        isPickup: true,
        date: '2017-05-31'
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
  })

  void it('Will prevent GET all recycles from this endpoint', async () => {
    const res = await request(app)
      .get('/api/Recycles')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.err, 'Sorry, this endpoint is not supported.')
  })

  void it('Will GET own existing recycle from this endpoint', async () => {
    const created = await request(app)
      .post('/api/Recycles')
      .set(userAuthHeader)
      .send({
        quantity: 100,
        AddressId: '1',
        UserId: userId,
        isPickup: false,
        date: '2017-06-01'
      })

    const res = await request(app)
      .get(`/api/Recycles/${created.body.data.id}`)
      .set(userAuthHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const items = res.body.data
    assert.equal(items.length, 1)
    for (const item of items) {
      assert.equal(item.id, created.body.data.id)
      assert.equal(item.UserId, userId)
      assert.equal(typeof item.AddressId, 'number')
      assert.equal(typeof item.quantity, 'number')
      assert.equal(typeof item.isPickup, 'boolean')
      assert.equal(typeof item.date, 'string')
      assert.equal(typeof item.createdAt, 'string')
      assert.equal(typeof item.updatedAt, 'string')
    }
  })

  void it('Will not GET a recycle without authentication', async () => {
    const res = await request(app)
      .get('/api/Recycles/1')
    assert.equal(res.status, 401)
    assert.ok(!JSON.stringify(res.body).includes('UserId'))
  })

  void it('Will not GET a recycle of another user', async () => {
    const res = await request(app)
      .get('/api/Recycles/1')
      .set(userAuthHeader)
    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [])
  })

  void it('Will reject JSON array or non-integer recycle ids', async () => {
    for (const id of ['[1,2,3]', encodeURIComponent('{"$gt":0}'), 'foobar', '1junk', '0', '-1', '1.5']) {
      const res = await request(app)
        .get(`/api/Recycles/${id}`)
        .set(userAuthHeader)
      assert.equal(res.status, 400, `id ${id}`)
    }
  })

  void it('PUT update existing recycle is forbidden', async () => {
    const res = await request(app)
      .put('/api/Recycles/1')
      .set(authHeader)
      .send({
        quantity: 100000
      })
    assert.equal(res.status, 401)
  })

  void it('DELETE existing recycle is forbidden', async () => {
    const res = await request(app)
      .delete('/api/Recycles/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })
})
