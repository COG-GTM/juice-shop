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

void describe('File system backed routes', () => {
  void it('GET /promotion advertises a rate limit', async () => {
    const res = await request(app)
      .get('/promotion')
    assert.equal(res.status, 200)
    assert.equal(res.headers['ratelimit-limit'], '300')
  })

  void it('GET /snippets/:challenge is rejected with 429 after 300 requests per minute', async () => {
    for (let i = 0; i < 300; i++) {
      const res = await request(app)
        .get('/snippets/directoryListingChallenge')
      assert.equal(res.status, 200)
    }
    const res = await request(app)
      .get('/snippets/directoryListingChallenge')
    assert.equal(res.status, 429)
  })

  void it('limits are tracked per route', async () => {
    const res = await request(app)
      .get('/snippets/fixes/directoryListingChallenge')
    assert.equal(res.status, 200)
  })
})
