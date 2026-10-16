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
let jimAuthHeader: Record<string, string>

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  jimAuthHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
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
    const res = await request(app)
      .get('/api/Recycles/1')
      .set(jimAuthHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const items = res.body.data
    assert.ok(Array.isArray(items))
    assert.equal(items.length, 1)
    for (const item of items) {
      assert.equal(item.id, 1)
      assert.equal(item.UserId, 2)
      assert.equal(typeof item.AddressId, 'number')
      assert.equal(typeof item.quantity, 'number')
      assert.equal(typeof item.isPickup, 'boolean')
      assert.ok(item.date !== undefined)
      assert.equal(typeof item.createdAt, 'string')
      assert.equal(typeof item.updatedAt, 'string')
    }
  })

  void it('GET recycle by id requires authentication', async () => {
    const res = await request(app)
      .get('/api/Recycles/1')
    assert.equal(res.status, 401)
  })

  void it('GET recycle by id does not return recycles of other users', async () => {
    const res = await request(app)
      .get('/api/Recycles/2')
      .set(jimAuthHeader)
    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [])
  })

  void it('GET recycle by id rejects JSON array ids used for bulk enumeration', async () => {
    const anonymous = await request(app)
      .get('/api/Recycles/' + encodeURIComponent('[1,2,3,4,5,6,7,8,9]'))
    assert.equal(anonymous.status, 401)

    const authenticated = await request(app)
      .get('/api/Recycles/' + encodeURIComponent('[1,2,3,4,5,6,7,8,9]'))
      .set(jimAuthHeader)
    assert.equal(authenticated.status, 400)
    assert.equal(authenticated.body.data, undefined)
  })

  void it('GET recycle by id rejects non-integer ids', async () => {
    for (const id of ['0', '-1', '1.5', '1e3', '{"$gt":0}', 'abc']) {
      const res = await request(app)
        .get('/api/Recycles/' + encodeURIComponent(id))
        .set(jimAuthHeader)
      assert.equal(res.status, 400, `expected 400 for id ${id}`)
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
