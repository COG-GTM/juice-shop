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
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/api/Complaints', () => {
  void it('POST new complaint', async () => {
    const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const res = await request(app)
      .post('/api/Complaints')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({
        message: 'You have no clue what https://github.com/eslint/eslint-scope/issues/39 means, do you???'
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
  })

  void it('POST complaint is always filed under the logged-in customer', async () => {
    const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const res = await request(app)
      .post('/api/Complaints')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({ UserId: 3, message: 'Forged complaint for bender' })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, security.decode(token).data.id)
  })

  void it('POST complaint with a token that carries no user is unauthorized', async () => {
    const res = await request(app)
      .post('/api/Complaints')
      .set(authHeader)
      .send({ message: 'No user' })
    assert.equal(res.status, 401)
  })

  void it('GET all complaints is forbidden via public API', async () => {
    const res = await request(app)
      .get('/api/Complaints')
    assert.equal(res.status, 401)
  })

  void it('GET complaints returns only the complaints of the logged-in customer', async () => {
    const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const jimId = security.decode(token).data.id
    const jimHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const created = await request(app)
      .post('/api/Complaints')
      .set(jimHeader)
      .send({ UserId: jimId, message: 'Jim\'s complaint' })
    assert.equal(created.status, 201)

    const res = await request(app)
      .get('/api/Complaints')
      .set(jimHeader)
    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.body.data))
    assert.ok(res.body.data.some((complaint: { id: number }) => complaint.id === created.body.data.id))
    for (const complaint of res.body.data) {
      assert.equal(complaint.UserId, jimId)
    }
  })

  void it('GET complaints does not leak other customers\' complaints', async () => {
    const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const res = await request(app)
      .get('/api/Complaints')
      .set({ Authorization: 'Bearer ' + token })
    assert.equal(res.status, 200)
    assert.ok(!res.body.data.some((complaint: { UserId: number }) => complaint.UserId === 3))
  })

  void it('GET complaints returns all complaints for an admin', async () => {
    const { token } = await login(app, { email: 'admin@juice-sh.op', password: 'admin123' })
    const res = await request(app)
      .get('/api/Complaints')
      .set({ Authorization: 'Bearer ' + token })
    assert.equal(res.status, 200)
    assert.ok(res.body.data.some((complaint: { UserId: number }) => complaint.UserId === 3))
    assert.ok(res.body.data.length >= 2)
  })

  void it('GET complaints with a token that carries no user is unauthorized', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set(authHeader)
    assert.equal(res.status, 401)
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
