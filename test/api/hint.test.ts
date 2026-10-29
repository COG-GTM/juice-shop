/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express
const jsonHeader = { 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/api/Hints/:id', () => {
  void it('PUT unlocking a hint is possible without being logged in', async () => {
    const res = await request(app)
      .put('/api/Hints/1')
      .set(jsonHeader)
      .send({ unlocked: true })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.unlocked, true)
  })

  void it('PUT ignores all fields other than unlocked', async () => {
    const before = await request(app).get('/api/Hints')
    const originalText = before.body.data.find((hint: { id: number }) => hint.id === 2).text
    const res = await request(app)
      .put('/api/Hints/2')
      .set(jsonHeader)
      .send({ unlocked: true, text: '<iframe src="javascript:alert(`xss`)">', ChallengeId: 1 })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.text, originalText)
    assert.notEqual(res.body.data.ChallengeId, 1)
  })

  void it('PUT changing anything but unlocking a hint is rejected', async () => {
    const res = await request(app)
      .put('/api/Hints/3')
      .set(jsonHeader)
      .send({ text: 'Tampered hint' })
    assert.equal(res.status, 400)
  })
})
