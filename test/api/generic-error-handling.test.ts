/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express
const originalNodeEnv = process.env.NODE_ENV

before(async () => {
  process.env.NODE_ENV = 'production'
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

after(() => {
  process.env.NODE_ENV = originalNodeEnv
})

void describe('Error handling outside development and test', () => {
  void it('unexpected path returns a generic error without stack trace', async () => {
    const res = await request(app).get('/rest/unrecognized')
    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/plain'))
    assert.equal(res.text, 'Internal Server Error')
  })

  void it('malformed JSON body returns 400 without stack trace', async () => {
    const res = await request(app).post('/rest/user/login')
      .set('Content-Type', 'application/json')
      .send('{"email":')
    assert.equal(res.status, 400)
    assert.equal(res.text, 'Bad Request')
    assert.ok(!res.text.includes('SyntaxError'))
  })
})
