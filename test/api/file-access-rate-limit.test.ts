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

const LIMIT = 300

async function exhaust (ip: string, path: string): Promise<void> {
  for (let i = 0; i < LIMIT; i++) {
    const res = await request(app).get(path).set('X-Forwarded-For', ip)
    assert.notEqual(res.status, 429, `request ${i + 1} was rate limited`)
  }
}

void describe('File access rate limiting', () => {
  void it('limits /ftp file requests per client', async () => {
    await exhaust('203.0.113.1', '/ftp/doesnotexist.md')
    const res = await request(app).get('/ftp/doesnotexist.md').set('X-Forwarded-For', '203.0.113.1')
    assert.equal(res.status, 429)
  })

  void it('shares the budget across all file-accessing routes', async () => {
    await exhaust('203.0.113.2', '/ftp/doesnotexist.md')
    for (const path of ['/ftp', '/encryptionkeys/doesnotexist.pub', '/support/logs', '/snippets/fixes/doesNotExist', '/snippets/doesNotExist', '/rest/languages', '/promotion', '/video', '/profile', '/dataerasure', '/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg', '/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us', '/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility', '/some/client/route']) {
      const res = await request(app).get(path).set('X-Forwarded-For', '203.0.113.2')
      assert.equal(res.status, 429, path)
    }
    for (const path of ['/file-upload', '/profile/image/file', '/profile/image/url', '/rest/memories', '/snippets/verdict', '/snippets/fixes', '/profile']) {
      const res = await request(app).post(path).set('X-Forwarded-For', '203.0.113.2')
      assert.equal(res.status, 429, `POST ${path}`)
    }
  })

  void it('counts a request only once when it falls through several limited routes', async () => {
    for (let i = 0; i < LIMIT; i++) {
      const res = await request(app).get('/dataerasure/doesnotexist').set('X-Forwarded-For', '203.0.113.5')
      assert.notEqual(res.status, 429, `request ${i + 1} was rate limited`)
    }
    const res = await request(app).get('/dataerasure/doesnotexist').set('X-Forwarded-For', '203.0.113.5')
    assert.equal(res.status, 429)
  })

  void it('does not limit other clients or non-file routes', async () => {
    await exhaust('203.0.113.3', '/ftp/doesnotexist.md')
    const other = await request(app).get('/ftp/doesnotexist.md').set('X-Forwarded-For', '203.0.113.4')
    assert.equal(other.status, 404)
    const api = await request(app).get('/rest/admin/application-version').set('X-Forwarded-For', '203.0.113.3')
    assert.equal(api.status, 200)
  })
})
