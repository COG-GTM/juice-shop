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

let app: Express
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }
const adminHeader = { Authorization: 'Bearer ' + security.authorize({ data: { id: 1, email: 'admin@juice-sh.op', role: 'admin' } }), 'content-type': 'application/json' }
const customerHeader = { Authorization: 'Bearer ' + security.authorize({ data: { id: 2, email: 'jim@juice-sh.op', role: 'customer' } }), 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/api/Complaints', () => {
  void it('POST new complaint', async () => {
    const res = await request(app)
      .post('/api/Complaints')
      .set(authHeader)
      .send({
        message: 'You have no clue what https://github.com/eslint/eslint-scope/issues/39 means, do you???'
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
  })

  void it('GET all complaints is forbidden via public API', async () => {
    const res = await request(app)
      .get('/api/Complaints')
    assert.equal(res.status, 401)
  })

  void it('GET all complaints as admin', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set(adminHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.data.some((complaint: { UserId: number }) => complaint.UserId === 3))
  })

  void it('GET complaints as customer only returns own complaints', async () => {
    const createRes = await request(app)
      .post('/api/Complaints')
      .set(customerHeader)
      .send({ UserId: 2, message: 'My own complaint' })
    assert.equal(createRes.status, 201)

    const res = await request(app)
      .get('/api/Complaints')
      .set(customerHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 0)
    for (const complaint of res.body.data) {
      assert.equal(complaint.UserId, 2)
    }
  })
})

void describe('/api/Complaints/:id', () => {
  void it('GET existing complaint by id is forbidden', async () => {
    const res = await request(app)
      .get('/api/Complaints/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })

  void it('PUT update existing complaint is forbidden', async () => {
    const res = await request(app)
      .put('/api/Complaints/1')
      .set(authHeader)
      .send({
        message: 'Should not work...'
      })
    assert.equal(res.status, 401)
  })

  void it('DELETE existing complaint is forbidden', async () => {
    const res = await request(app)
      .delete('/api/Complaints/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })
})
