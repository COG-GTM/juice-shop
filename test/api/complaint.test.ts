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
let jimAuthHeader: Record<string, string>
let benderAuthHeader: Record<string, string>

before(async () => {
  const result = await createTestApp()
  app = result.app

  const jim = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  jimAuthHeader = { Authorization: 'Bearer ' + jim.token, 'content-type': 'application/json' }
  const bender = await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })
  benderAuthHeader = { Authorization: 'Bearer ' + bender.token, 'content-type': 'application/json' }
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

  void it('GET complaints with a token lacking a user id is forbidden', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set(authHeader)
    assert.equal(res.status, 403)
  })

  void it('GET complaints only returns complaints of the logged-in user', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set(jimAuthHeader)
    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.body.data))
    assert.ok(res.body.data.every((complaint: { UserId: number }) => complaint.UserId === 2))
  })

  void it('GET complaints returns own complaints for their owner', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set(benderAuthHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 0)
    assert.ok(res.body.data.every((complaint: { UserId: number }) => complaint.UserId === 3))
  })

  void it('GET complaints ignores UserId query parameter of other users', async () => {
    const res = await request(app)
      .get('/api/Complaints?UserId=3')
      .set(jimAuthHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.data.every((complaint: { UserId: number }) => complaint.UserId === 2))
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
