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

void describe('file system access rate limiting', () => {
  const fileAccessRoutes = [
    '/ftp',
    '/ftp/acquisitions.md',
    '/encryptionkeys/premium.key',
    '/support/logs',
    '/promotion',
    '/video',
    '/snippets/scoreBoardChallenge',
    '/rest/languages',
    '/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg',
    '/some/unknown/client/route'
  ]

  for (const route of fileAccessRoutes) {
    void it(`GET ${route} is rate-limited`, async () => {
      const res = await request(app).get(route)
      assert.equal(res.headers['x-ratelimit-limit'], '200')
    })
  }

  void it('POST /file-upload is rate-limited', async () => {
    const res = await request(app).post('/file-upload')
    assert.equal(res.headers['x-ratelimit-limit'], '200')
  })

  void it('POST /profile/image/file is rate-limited', async () => {
    const res = await request(app).post('/profile/image/file')
    assert.equal(res.headers['x-ratelimit-limit'], '200')
  })

  void it('rejects requests to /ftp/:file with 429 once the limit is exceeded', async () => {
    const first = await request(app).get('/ftp/acquisitions.md')
    assert.equal(first.status, 200)
    const remaining = Number(first.headers['x-ratelimit-remaining'])
    assert.ok(remaining > 0)
    for (let i = 0; i < remaining; i++) {
      const res = await request(app).get('/ftp/acquisitions.md')
      assert.equal(res.status, 200)
    }
    const res = await request(app).get('/ftp/acquisitions.md')
    assert.equal(res.status, 429)
  })

  void it('does not rate-limit API routes without file system access', async () => {
    const res = await request(app).get('/rest/products/search?q=')
    assert.equal(res.headers['x-ratelimit-limit'], undefined)
  })
})
