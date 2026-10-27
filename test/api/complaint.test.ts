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
let otherAuthHeader: { Authorization: string, 'content-type': string }
let userId: number
let otherUserId: number

before(async () => {
  const result = await createTestApp()
  app = result.app
  const jim = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  authHeader = { Authorization: 'Bearer ' + jim.token, 'content-type': 'application/json' }
  userId = security.decode(jim.token).data.id
  const bender = await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })
  otherAuthHeader = { Authorization: 'Bearer ' + bender.token, 'content-type': 'application/json' }
  otherUserId = security.decode(bender.token).data.id
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

  void it('POST new complaint ignores UserId from request body', async () => {
    const res = await request(app)
      .post('/api/Complaints')
      .set(authHeader)
      .send({ UserId: otherUserId, message: 'Spoofed complaint' })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, userId)
  })

  void it('GET all complaints only returns complaints of the logged-in user', async () => {
    await request(app)
      .post('/api/Complaints')
      .set(otherAuthHeader)
      .send({ message: 'Complaint of another user' })
    const res = await request(app)
      .get('/api/Complaints')
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 0)
    assert.ok(res.body.data.every((complaint: { UserId: number }) => complaint.UserId === userId))
  })

  void it('GET all complaints cannot be widened to another user via query parameter', async () => {
    const res = await request(app)
      .get(`/api/Complaints?UserId=${otherUserId}`)
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.data.every((complaint: { UserId: number }) => complaint.UserId === userId))
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
