/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
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
  void it('GET generic error message without information leakage when calling unrecognized path with /rest in it', async () => {
    const res = await request(app)
      .get('/rest/unrecognized')
    assert.equal(res.status, 500)
    assert.ok(!res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.equal(res.text, 'Internal Server Error')
    assert.ok(!res.text.includes('node_modules'))
  })

  void it('GET generic JSON error without stack trace when calling unrecognized path with /rest in it', async () => {
    const res = await request(app)
      .get('/rest/unrecognized')
      .set('Accept', 'application/json')
    assert.equal(res.status, 500)
    assert.deepEqual(res.body, { error: { message: 'Internal Server Error' } })
    assert.ok(!res.text.includes('stack'))
    assert.ok(!res.text.includes('Unexpected path'))
  })
})
