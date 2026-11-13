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

void describe('File serving rate limit', () => {
  void it('GET /ftp/legal.md exposes rate limit headers', async () => {
    const res = await request(app).get('/ftp/legal.md')
    assert.equal(res.status, 200)
    assert.ok(res.headers.ratelimit?.includes('limit=300'))
    assert.ok(res.headers['ratelimit-policy']?.includes('300;w=60'))
  })

  void it('GET on file serving routes is rejected with 429 once 300 requests per minute are exceeded', async () => {
    const paths = ['/ftp/legal.md', '/.well-known/csaf/provider-metadata.json', '/encryptionkeys/jwt.pub', '/support/logs']
    for (let i = 1; i < 300; i++) {
      const res = await request(app).get(paths[i % paths.length])
      assert.notEqual(res.status, 429, `request ${i + 1} to ${paths[i % paths.length]} was rate limited`)
    }
    for (const path of paths) {
      const res = await request(app).get(path)
      assert.equal(res.status, 429, `${path} was not rate limited`)
      assert.ok(res.headers['retry-after'])
    }
  })

  void it('GET on routes without file serving is not rate limited', async () => {
    const res = await request(app).get('/rest/admin/application-version')
    assert.equal(res.status, 200)
  })
})
