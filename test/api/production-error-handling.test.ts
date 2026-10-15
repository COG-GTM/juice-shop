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
  delete process.env.NODE_ENV
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

after(() => {
  process.env.NODE_ENV = originalNodeEnv
})

void describe('Error handling outside development and test', () => {
  void it('unexpected path returns a generic error without stack trace or framework version', async () => {
    const res = await request(app).get('/rest/unrecognized')
    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>500 Internal Server Error</h1>'))
    assert.ok(!res.text.includes('Unexpected path'))
    assert.ok(!res.text.includes('(Express'))
    assert.ok(!res.text.includes('.ts:'))
  })

  void it('status code of handled errors is preserved', async () => {
    const res = await request(app).get('/ftp/package.json.bak')
    assert.equal(res.status, 403)
    assert.ok(res.text.includes('<h1>403 Forbidden</h1>'))
    assert.ok(!res.text.includes('Only .md and .pdf files are allowed'))
  })
})
