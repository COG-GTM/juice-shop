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
let adminHeader: Record<string, string>
let customerHeader: Record<string, string>

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token: adminToken } = await login(app, { email: 'admin@juice-sh.op', password: 'admin123' })
  adminHeader = { Authorization: 'Bearer ' + adminToken, 'content-type': 'application/json' }
  const { token: customerToken } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  customerHeader = { Authorization: 'Bearer ' + customerToken, 'content-type': 'application/json' }
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

  void it('POST new complaint as customer', async () => {
    const res = await request(app)
      .post('/api/Complaints')
      .set(customerHeader)
      .send({
        message: 'My order arrived squashed.'
      })
    assert.equal(res.status, 201)
  })

  void it('GET all complaints is forbidden for customers', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set(customerHeader)
    assert.equal(res.status, 403)
    assert.equal(res.body.data, undefined)
  })

  void it('GET all complaints is forbidden for tokens without admin role', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set(authHeader)
    assert.equal(res.status, 403)
  })

  void it('GET all complaints as admin', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set(adminHeader)
    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.body.data))
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
