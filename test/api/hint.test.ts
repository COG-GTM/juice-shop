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

let app: Express
const authHeader = { Authorization: `Bearer ${security.authorize()}`, 'content-type': 'application/json' }
const jsonHeader = { 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function firstHintId (): Promise<number> {
  const res = await request(app).get('/api/Hints')
  return res.body.data[0].id
}

void describe('/api/Hints', () => {
  void it('GET all hints', async () => {
    const res = await request(app)
      .get('/api/Hints')

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.status, 'success')
    assert.ok(Array.isArray(res.body.data))
    assert.ok(res.body.data.length > 0)
    for (const item of res.body.data) {
      assert.equal(typeof item.id, 'number')
      assert.equal(typeof item.ChallengeId, 'number')
      assert.equal(typeof item.text, 'string')
      assert.ok(item.text.length > 0)
      assert.equal(typeof item.order, 'number')
      assert.equal(typeof item.unlocked, 'boolean')
    }
  })

  void it('GET all hints passes every hint text through the translation hook', async () => {
    const res = await request(app)
      .get('/api/Hints')
      .set('Accept-Language', 'de_DE')

    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.body.data))
    for (const item of res.body.data) {
      assert.equal(typeof item.text, 'string')
      assert.ok(item.text.length > 0)
    }
  })

  void it('POST new hint is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .post('/api/Hints')
      .set(authHeader)
      .send({ ChallengeId: 1, text: 'Just look at the code!', order: 1, unlocked: false })

    assert.equal(res.status, 401)
  })
})

void describe('/api/Hints/:id', () => {
  void it('GET existing hint by id is forbidden via public API', async () => {
    const res = await request(app)
      .get(`/api/Hints/${await firstHintId()}`)

    assert.equal(res.status, 401)
  })

  void it('GET existing hint by id is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get(`/api/Hints/${await firstHintId()}`)
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('PUT unlock existing hint is allowed for anonymous users', async () => {
    const id = await firstHintId()
    const res = await request(app)
      .put(`/api/Hints/${id}`)
      .set(jsonHeader)
      .send({ unlocked: true })

    assert.equal(res.status, 200)
    assert.equal(res.body.status, 'success')
    assert.equal(res.body.data.id, id)
    assert.equal(res.body.data.unlocked, true)
  })

  void it('PUT unlock existing hint is allowed when authenticated', async () => {
    const id = await firstHintId()
    const res = await request(app)
      .put(`/api/Hints/${id}`)
      .set(authHeader)
      .send({ unlocked: true })

    assert.equal(res.status, 200)
    assert.equal(res.body.data.unlocked, true)
  })

  void it('DELETE existing hint is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .delete(`/api/Hints/${await firstHintId()}`)
      .set(authHeader)

    assert.equal(res.status, 401)
  })
})
