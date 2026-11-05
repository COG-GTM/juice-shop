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

  void it('POST new complaint ignores passed user ID and is associated with current user', async () => {
    const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const res = await request(app)
      .post('/api/Complaints')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({ UserId: 3, message: 'Filed in Bender\'s name' })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, 2)
  })

  void it('POST new complaint with token of unknown user fails', async () => {
    const res = await request(app)
      .post('/api/Complaints')
      .set(authHeader)
      .send({ message: 'Nobody filed this' })
    assert.equal(res.status, 401)
  })

  void it('GET all complaints is forbidden via public API', async () => {
    const res = await request(app)
      .get('/api/Complaints')
    assert.equal(res.status, 401)
  })

  void it('GET complaints with token of unknown user fails', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set({ Authorization: 'Bearer ' + security.authorize() })
    assert.equal(res.status, 401)
  })

  void it('GET complaints only returns complaints of current user', async () => {
    const { token: bjoernToken } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
    const createRes = await request(app)
      .post('/api/Complaints')
      .set({ Authorization: 'Bearer ' + bjoernToken, 'content-type': 'application/json' })
      .send({ message: 'My private complaint' })
    assert.equal(createRes.status, 201)

    const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const res = await request(app)
      .get('/api/Complaints')
      .set({ Authorization: 'Bearer ' + token })
    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 0)
    assert.ok(res.body.data.every((complaint: { UserId: number }) => complaint.UserId === 2))
    assert.ok(!res.body.data.some((complaint: { id: number }) => complaint.id === createRes.body.data.id))
  })

  void it('GET complaints with admin-role token of unknown user fails', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set({ Authorization: 'Bearer ' + security.authorize({ data: { id: 1, role: security.roles.admin } }) })
    assert.equal(res.status, 401)
  })

  void it('GET all complaints as admin', async () => {
    const { token } = await login(app, { email: 'admin@juice-sh.op', password: 'admin123' })
    const res = await request(app)
      .get('/api/Complaints')
      .set({ Authorization: 'Bearer ' + token })
    assert.equal(res.status, 200)
    assert.ok(res.body.data.some((complaint: { UserId: number }) => complaint.UserId !== 1))
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
