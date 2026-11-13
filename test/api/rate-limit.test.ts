/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'

const LIMIT = 5

async function createLimitedApp (): Promise<Express> {
  process.env.NODE_CONFIG = JSON.stringify({ server: { rateLimit: { windowMs: 60000, max: LIMIT } } })
  const { createTestApp } = await import('./helpers/setup')
  return (await createTestApp()).app
}

let app: Express

async function exhaustLimit (): Promise<void> {
  for (let i = 0; i <= LIMIT; i++) {
    await request(app).get('/ftp/legal.md')
  }
}

before(async () => {
  app = await createLimitedApp()
}, { timeout: 60000 })

void describe('Global rate limiting', () => {
  void it('rejects file-serving requests beyond the limit with 429', async () => {
    for (let i = 0; i < LIMIT; i++) {
      const res = await request(app).get('/ftp/legal.md')
      assert.equal(res.status, 200)
      assert.ok(res.headers.ratelimit)
    }
    const res = await request(app).get('/ftp/legal.md')
    assert.equal(res.status, 429)
  })

  void it('cannot be bypassed by rotating X-Forwarded-For', async () => {
    await exhaustLimit()
    for (let i = 0; i < 3; i++) {
      const res = await request(app)
        .get('/ftp/legal.md')
        .set('X-Forwarded-For', `10.0.0.${i + 1}`)
      assert.equal(res.status, 429)
    }
  })

  void it('applies to all routes, not just file serving', async () => {
    await exhaustLimit()
    const res = await request(app).get('/rest/admin/application-version')
    assert.equal(res.status, 429)
  })
})
