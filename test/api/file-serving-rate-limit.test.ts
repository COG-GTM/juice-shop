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

void describe('File serving rate limiting', () => {
  void it('GET /ftp/legal.md exhausts the shared file serving budget after 100 requests per minute', async () => {
    for (let i = 0; i < 100; i++) {
      const res = await request(app).get('/ftp/legal.md')
      assert.equal(res.status, 200)
    }
    const res = await request(app).get('/ftp/legal.md')
    assert.equal(res.status, 429)

    for (const path of ['/ftp', '/ftp/quarantine/juicy_malware_linux_amd_64.url', '/.well-known/csaf/provider-metadata.json', '/encryptionkeys/jwt.pub', '/support/logs']) {
      const res = await request(app).get(path)
      assert.equal(res.status, 429, path)
    }
  })

  void it('other routes are not affected by the file serving rate limit', async () => {
    const res = await request(app).get('/rest/products/search?q=')
    assert.equal(res.status, 200)
  })
})
