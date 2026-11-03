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
const jimUserId = 2

before(async () => {
  const result = await createTestApp()
  app = result.app

  const { token } = await login(app, {
    email: 'jim@juice-sh.op',
    password: 'ncc-1701'
  })
  authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
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

  void it('GET all complaints', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('POST new complaint is always filed under the logged-in user', async () => {
    const res = await request(app)
      .post('/api/Complaints')
      .set(authHeader)
      .send({
        UserId: 3,
        message: 'Filed in someone else\'s name?'
      })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, jimUserId)
  })

  void it('GET all complaints only returns complaints of the logged-in user', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 0)
    for (const complaint of res.body.data) {
      assert.equal(complaint.UserId, jimUserId)
    }
  })

  void it('GET all complaints with a valid token not issued via login in this process', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set({ Authorization: 'Bearer ' + security.authorize({ data: { id: jimUserId, email: 'jim@juice-sh.op' } }) })
    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 0)
    for (const complaint of res.body.data) {
      assert.equal(complaint.UserId, jimUserId)
    }
  })

  void it('GET all complaints with a token without user id is rejected', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set({ Authorization: 'Bearer ' + security.authorize() })
    assert.equal(res.status, 401)
  })

  void it('GET all complaints ignores nested UserId filter of other users', async () => {
    const res = await request(app)
      .get('/api/Complaints?UserId[ne]=2&UserId[eq]=3')
      .set(authHeader)
    assert.equal(res.status, 200)
    for (const complaint of res.body.data) {
      assert.equal(complaint.UserId, jimUserId)
    }
  })

  void it('GET all complaints ignores UserId query parameter of other users', async () => {
    const res = await request(app)
      .get('/api/Complaints?UserId=3')
      .set(authHeader)
    assert.equal(res.status, 200)
    for (const complaint of res.body.data) {
      assert.equal(complaint.UserId, jimUserId)
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
