/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let otherAuthHeader: { Authorization: string, 'content-type': string }
let jimUserId: number
let jimComplaintId: number
let otherComplaintId: number

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
  jimUserId = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString()).data.id

  await register(app, {
    email: 'complaint-tester@example.com',
    password: 'complaint-test'
  })
  const { token: otherToken } = await login(app, {
    email: 'complaint-tester@example.com',
    password: 'complaint-test'
  })
  otherAuthHeader = {
    Authorization: 'Bearer ' + otherToken,
    'content-type': 'application/json'
  }
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
    assert.equal(res.body.data.UserId, jimUserId)
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
    jimComplaintId = res.body.data.id
  })

  void it('POST new complaint with forged UserId is attributed to the caller', async () => {
    const res = await request(app)
      .post('/api/Complaints')
      .set(authHeader)
      .send({
        message: 'Forged complaint in the name of the admin',
        UserId: 1
      })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, jimUserId)
  })

  void it('POST new complaint as a different user', async () => {
    const res = await request(app)
      .post('/api/Complaints')
      .set(otherAuthHeader)
      .send({
        message: 'Another user\'s complaint'
      })
    assert.equal(res.status, 201)
    otherComplaintId = res.body.data.id
  })

  void it('GET all complaints is forbidden via public API', async () => {
    const res = await request(app)
      .get('/api/Complaints')
    assert.equal(res.status, 401)
  })

  void it('GET all complaints only returns complaints of the calling user', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.body.data))
    assert.ok(res.body.data.some((complaint: { id: number }) => complaint.id === jimComplaintId))
    assert.ok(!res.body.data.some((complaint: { id: number }) => complaint.id === otherComplaintId))
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
