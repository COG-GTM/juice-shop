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

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/api', () => {
  void it('GET error when query /api without actual resource', async () => {
    const res = await request(app)
      .get('/api')
    assert.equal(res.status, 500)
  })
})

void describe('/rest', () => {
  void it('GET generic error message without stack trace or framework version when calling unrecognized path with /rest in it', async () => {
    const res = await request(app)
      .get('/rest/unrecognized')
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Internal Server Error'))
    assert.ok(!res.text.includes('Express'))
    assert.ok(!res.text.includes('Unexpected path'))
    assert.ok(!res.text.includes('stacktrace'))
  })

  void it('GET generic JSON error for API clients calling unrecognized path with /rest in it', async () => {
    const res = await request(app)
      .get('/rest/unrecognized')
      .set('Accept', 'application/json')
    assert.equal(res.status, 500)
    assert.deepEqual(res.body, { error: { status: 500, message: 'Internal Server Error' } })
  })
})
