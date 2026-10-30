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
let jimAuthHeader: { Authorization: string, 'content-type': string }
let benderAuthHeader: { Authorization: string, 'content-type': string }

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
      .set(jimAuthHeader)
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

  void it('GET complaints only returns those of the logged-in user', async () => {
    const jimPost = await request(app)
      .post('/api/Complaints')
      .set(jimAuthHeader)
      .send({ message: 'Jim complaint' })
    assert.equal(jimPost.status, 201)
    const benderPost = await request(app)
      .post('/api/Complaints')
      .set(benderAuthHeader)
      .send({ message: 'Bender complaint', UserId: jimPost.body.data.UserId })
    assert.equal(benderPost.status, 201)
    assert.notEqual(benderPost.body.data.UserId, jimPost.body.data.UserId)

    const jimRes = await request(app)
      .get('/api/Complaints')
      .set(jimAuthHeader)
    assert.equal(jimRes.status, 200)
    assert.ok(jimRes.body.data.length > 0)
    assert.ok(jimRes.body.data.every((c: { UserId: number }) => c.UserId === jimPost.body.data.UserId))
    assert.ok(jimRes.body.data.some((c: { id: number }) => c.id === jimPost.body.data.id))
    assert.ok(!jimRes.body.data.some((c: { id: number }) => c.id === benderPost.body.data.id))

    const benderRes = await request(app)
      .get('/api/Complaints')
      .set(benderAuthHeader)
    assert.equal(benderRes.status, 200)
    assert.ok(benderRes.body.data.every((c: { UserId: number }) => c.UserId === benderPost.body.data.UserId))
    assert.ok(benderRes.body.data.some((c: { id: number }) => c.id === benderPost.body.data.id))
    assert.ok(!benderRes.body.data.some((c: { id: number }) => c.id === jimPost.body.data.id))
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
