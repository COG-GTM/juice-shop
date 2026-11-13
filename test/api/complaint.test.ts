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
let jimHeader: Record<string, string>
let benderHeader: Record<string, string>

before(async () => {
  const result = await createTestApp()
  app = result.app
  const jim = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  jimHeader = { Authorization: 'Bearer ' + jim.token, 'content-type': 'application/json' }
  const bender = await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })
  benderHeader = { Authorization: 'Bearer ' + bender.token, 'content-type': 'application/json' }
}, { timeout: 60000 })

void describe('/api/Complaints', () => {
  void it('POST new complaint', async () => {
    const res = await request(app)
      .post('/api/Complaints')
      .set(jimHeader)
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

  void it('GET all complaints only returns complaints of the current user', async () => {
    const createRes = await request(app)
      .post('/api/Complaints')
      .set(jimHeader)
      .send({ message: 'Jim complains in private' })
    assert.equal(createRes.status, 201)

    const jimRes = await request(app)
      .get('/api/Complaints')
      .set(jimHeader)
    assert.equal(jimRes.status, 200)
    assert.ok(jimRes.body.data.length > 0)
    assert.ok(jimRes.body.data.every((complaint: { UserId: number }) => complaint.UserId === jimRes.body.data[0].UserId))

    const benderRes = await request(app)
      .get('/api/Complaints')
      .set(benderHeader)
    assert.equal(benderRes.status, 200)
    assert.ok(benderRes.body.data.every((complaint: { id: number }) => complaint.id !== createRes.body.data.id))
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
