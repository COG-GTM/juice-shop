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
  void it('PUT changing hint text is forbidden', async () => {
    const res = await request(app)
      .put('/api/Hints/1')
      .set(jsonHeader)
      .send({ text: 'Defaced hint' })
    assert.equal(res.status, 403)
  })

  void it('PUT unlocking hint together with other fields is forbidden', async () => {
    const res = await request(app)
      .put('/api/Hints/1')
      .set(jsonHeader)
      .send({ unlocked: true, text: 'Defaced hint' })
    assert.equal(res.status, 403)
  })

  void it('PUT unlocking hint is allowed', async () => {
    const res = await request(app)
      .put('/api/Hints/1')
      .set(jsonHeader)
      .send({ unlocked: true })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.unlocked, true)
    assert.notEqual(res.body.data.text, 'Defaced hint')
  })
})
