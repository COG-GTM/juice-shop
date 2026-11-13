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

void describe('File access rate limiting', () => {
  void it('GET /ftp/legal.md exposes rate limit headers', async () => {
    const res = await request(app).get('/ftp/legal.md')
    assert.equal(res.status, 200)
    assert.ok(res.headers['ratelimit-policy']?.includes('300'))
    assert.ok(res.headers.ratelimit)
  })

  void it('file access routes share a per-client budget that X-Forwarded-For cannot reset', async () => {
    const statuses: number[] = []
    for (let i = 0; i < 299; i++) {
      const paths = ['/ftp/legal.md', '/snippets/fixes/directoryListingChallenge', '/promotion', '/encryptionkeys/jwt.pub']
      const res = await request(app).get(paths[i % paths.length]).set('X-Forwarded-For', `10.0.${Math.floor(i / 256)}.${i % 256}`)
      statuses.push(res.status)
    }
    assert.equal(statuses.filter(s => s === 429).length, 0)

    for (const path of ['/ftp/legal.md', '/snippets/directoryListingChallenge', '/video', '/support/logs', '/profile', '/some/angular/route']) {
      const res = await request(app).get(path).set('X-Forwarded-For', '203.0.113.7')
      assert.equal(res.status, 429, path)
    }
  })

  void it('routes without file system access stay unaffected', async () => {
    const res = await request(app).get('/rest/products/search?q=')
    assert.equal(res.status, 200)
  })
})
