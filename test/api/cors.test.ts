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
  process.env.CORS_ALLOWED_ORIGINS = 'https://trusted.example, http://localhost:4200/'
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('CORS', () => {
  void it('does not reflect an unknown origin', async () => {
    const res = await request(app)
      .get('/rest/admin/application-version')
      .set('Origin', 'https://evil.example')

    assert.equal(res.status, 200)
    assert.equal(res.headers['access-control-allow-origin'], undefined)
    assert.equal(res.headers['access-control-allow-credentials'], undefined)
  })

  void it('rejects preflight from an unknown origin', async () => {
    const res = await request(app)
      .options('/rest/user/login')
      .set('Origin', 'https://evil.example')
      .set('Access-Control-Request-Method', 'POST')

    assert.equal(res.headers['access-control-allow-origin'], undefined)
  })

  void it('allows the configured base URL origin', async () => {
    const res = await request(app)
      .get('/rest/admin/application-version')
      .set('Origin', 'http://localhost:3000')

    assert.equal(res.status, 200)
    assert.equal(res.headers['access-control-allow-origin'], 'http://localhost:3000')
    assert.equal(res.headers['access-control-allow-credentials'], undefined)
  })

  void it('allows origins from CORS_ALLOWED_ORIGINS, ignoring whitespace and trailing slashes', async () => {
    for (const origin of ['https://trusted.example', 'http://localhost:4200']) {
      const res = await request(app)
        .options('/rest/user/login')
        .set('Origin', origin)
        .set('Access-Control-Request-Method', 'POST')

      assert.equal(res.status, 204)
      assert.equal(res.headers['access-control-allow-origin'], origin)
    }
  })

  void it('never uses a wildcard origin', async () => {
    const res = await request(app)
      .get('/rest/admin/application-version')
      .set('Origin', 'http://localhost:3000')

    assert.notEqual(res.headers['access-control-allow-origin'], '*')
  })

  void it('serves requests without an Origin header normally', async () => {
    const res = await request(app)
      .get('/rest/admin/application-version')

    assert.equal(res.status, 200)
    assert.equal(res.headers['access-control-allow-origin'], undefined)
  })
})
