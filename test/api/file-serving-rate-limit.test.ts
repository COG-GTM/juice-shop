/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

const LIMIT = 300
const EASTER_EGG = '/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('file-serving rate limit', () => {
  void it('GET /promotion and /video are served before the limit is reached', async () => {
    assert.equal((await request(app).get('/promotion')).status, 200)
    assert.equal((await request(app).get('/video')).status, 200)
  })

  void it('blocks file-serving routes once the shared per-client limit is exhausted, even with rotating X-Forwarded-For', async () => {
    for (let i = 2; i < LIMIT; i++) {
      const res = await request(app).get(EASTER_EGG).set('X-Forwarded-For', `10.0.${Math.floor(i / 256)}.${i % 256}`)
      assert.equal(res.status, 200, `request ${i + 1} should not be limited`)
    }

    for (const path of ['/promotion', '/video', EASTER_EGG]) {
      const res = await request(app).get(path).set('X-Forwarded-For', '203.0.113.7')
      assert.equal(res.status, 429, `${path} should be rate limited`)
    }
  })

  void it('does not limit unrelated routes', async () => {
    const res = await request(app).get('/rest/languages')
    assert.equal(res.status, 200)
  })
})
