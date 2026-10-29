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
let jimId: number
let jimAuthHeader: { Authorization: string, 'content-type': string }
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app

  const { token } = await login(app, {
    email: 'jim@juice-sh.op',
    password: 'ncc-1701'
  })
  jimId = security.decode(token).data.id
  jimAuthHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
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

  void it('GET complaints only returns complaints of the logged-in user', async () => {
    const postRes = await request(app)
      .post('/api/Complaints')
      .set(jimAuthHeader)
      .send({ UserId: jimId, message: 'My order arrived squashed.' })
    assert.equal(postRes.status, 201)

    const res = await request(app)
      .get('/api/Complaints')
      .set(jimAuthHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 0)
    assert.ok(res.body.data.some((complaint: { message: string }) => complaint.message === 'My order arrived squashed.'))
    for (const complaint of res.body.data) {
      assert.equal(complaint.UserId, jimId)
    }
  })

  void it('GET complaints is forbidden for tokens not bound to a known user', async () => {
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
