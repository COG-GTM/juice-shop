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

void describe('global rate limit', () => {
  void it('applies to authorization-checked REST routes', async () => {
    const res = await request(app)
      .get('/rest/basket/1')

    assert.equal(res.status, 401)
    assert.match(res.headers.ratelimit, new RegExp(`limit=${config.get<number>('server.rateLimit.max')}, remaining=\\d+`))
  })

  void it('applies to authorization-checked API routes', async () => {
    const res = await request(app)
      .get('/api/Users')

    assert.equal(res.status, 401)
    assert.match(res.headers.ratelimit, /limit=\d+, remaining=\d+/)
  })
})
