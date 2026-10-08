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

void describe('Error handling outside development', () => {
  void it('unexpected path returns a generic error without stack trace or internals', async () => {
    const res = await request(app).get('/rest/unrecognized')
    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/plain'))
    assert.equal(res.text, 'Internal Server Error')
    assert.ok(!res.text.includes('Unexpected path'))
    assert.ok(!res.text.includes('(Express'))
  })

  void it('error status codes of handled errors are preserved', async () => {
    const res = await request(app).get('/ftp/package.json.bak')
    assert.equal(res.status, 403)
    assert.equal(res.text, 'Forbidden')
  })
})
