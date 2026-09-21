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
let userId: number

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token } = await login(app, { email: 'demo', password: 'demo' })
  authHeader = { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
  const whoami = await request(app).get('/rest/user/whoami').set(authHeader)
  userId = whoami.body.user.id
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
      .set(authHeader)
      .send({
        quantity: 100,
        AddressId: '1',
        UserId: userId,
        isPickup: false,
        date: '2017-06-01'
      })

    const res = await request(app)
      .get(`/api/Recycles/${created.body.data.id}`)
      .set(authHeader)
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
      assert.ok(item.date !== undefined)
      assert.equal(typeof item.createdAt, 'string')
      assert.equal(typeof item.updatedAt, 'string')
    }
  })

  void it('Will not GET existing recycle without authentication', async () => {
    const res = await request(app)
      .get('/api/Recycles/1')
    assert.equal(res.status, 401)
  })

  void it('Will not GET recycle of another user', async () => {
    const created = await request(app)
      .post('/api/Recycles')
      .set(authHeader)
      .send({
        quantity: 50,
        AddressId: '1',
        UserId: userId + 1,
        isPickup: false,
        date: '2017-06-02'
      })

    const res = await request(app)
      .get(`/api/Recycles/${created.body.data.id}`)
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [])
  })

  void it('Will reject non-numeric recycle id', async () => {
    const res = await request(app)
      .get('/api/Recycles/foobar')
      .set(authHeader)
    assert.equal(res.status, 400)
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
