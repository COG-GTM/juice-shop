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
let userId: number

before(async () => {
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
  userId = (security.decode(token) as any).data.id
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

  void it('GET existing recycle is forbidden for anonymous users', async () => {
    const res = await request(app)
      .get('/api/Recycles/1')
    assert.equal(res.status, 401)
  })

  void it('Will GET own recycle from this endpoint', async () => {
    const created = await request(app)
      .post('/api/Recycles')
      .set(authHeader)
      .send({
        UserId: userId,
        quantity: 100,
        AddressId: '1',
        isPickup: false,
        date: '2017-06-01'
      })
    assert.equal(created.status, 201)

    const res = await request(app)
      .get(`/api/Recycles/${created.body.data.id}`)
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const items = res.body.data
    assert.ok(Array.isArray(items))
    assert.equal(items.length, 1)
    for (const item of items) {
      assert.equal(typeof item.id, 'number')
      assert.equal(item.UserId, userId)
      assert.equal(typeof item.AddressId, 'number')
      assert.equal(typeof item.quantity, 'number')
      assert.equal(typeof item.isPickup, 'boolean')
      assert.ok(item.date !== undefined)
      assert.equal(typeof item.createdAt, 'string')
      assert.equal(typeof item.updatedAt, 'string')
    }
  })

  void it('Will not GET recycle of another user', async () => {
    const created = await request(app)
      .post('/api/Recycles')
      .set(authHeader)
      .send({
        UserId: userId + 1,
        quantity: 42,
        AddressId: '1',
        isPickup: false,
        date: '2017-06-02'
      })
    assert.equal(created.status, 201)

    const res = await request(app)
      .get(`/api/Recycles/${created.body.data.id}`)
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [])
  })

  void it('GET recycle with non-numeric id is rejected', async () => {
    const res = await request(app)
      .get('/api/Recycles/foo')
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
