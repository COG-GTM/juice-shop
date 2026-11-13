/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express
let authHeader: Record<string, string>

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token } = await login(app, { email: 'admin@juice-sh.op', password: 'admin123' })
  authHeader = { Authorization: `Bearer ${token}` }
}, { timeout: 60000 })

void describe('File access rate limiting', () => {
  const rateLimitedRoutes: Array<['get' | 'post', string]> = [
    ['get', '/ftp'],
    ['get', '/ftp/legal.md'],
    ['get', '/encryptionkeys'],
    ['get', '/encryptionkeys/jwt.pub'],
    ['get', '/support/logs'],
    ['get', '/.well-known/csaf/provider-metadata.json'],
    ['get', '/promotion'],
    ['get', '/profile'],
    ['get', '/rest/languages'],
    ['get', '/snippets/scoreBoardChallenge'],
    ['post', '/snippets/verdict'],
    ['get', '/snippets/fixes/scoreBoardChallenge'],
    ['post', '/snippets/fixes'],
    ['get', '/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg'],
    ['post', '/file-upload'],
    ['post', '/profile/image/file'],
    ['post', '/profile/image/url'],
    ['post', '/rest/basket/1/checkout'],
    ['get', '/some/angular/deep/link']
  ]

  for (const [method, route] of rateLimitedRoutes) {
    void it(`${method.toUpperCase()} ${route} is rate limited`, async () => {
      const res = await request(app)[method](route).set(authHeader)
      assert.equal(res.headers['ratelimit-policy'], '300;w=60')
      assert.ok(res.headers.ratelimit)
    })
  }

  void it('answers 429 once the per-client budget is exhausted, regardless of X-Forwarded-For', async () => {
    let allowed = 0
    let status = 200
    while (status !== 429 && allowed <= 300) {
      status = (await request(app).get('/promotion')).status
      if (status !== 429) allowed++
    }
    assert.equal(status, 429)
    assert.ok(allowed > 0 && allowed <= 300)

    const spoofed = await request(app).get('/ftp/legal.md').set('X-Forwarded-For', '203.0.113.7')
    assert.equal(spoofed.status, 429)
  })
})
