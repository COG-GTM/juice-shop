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

void describe('file serving rate limit', () => {
  void it('throttles file downloads and directory listings per client after 300 requests per minute', async () => {
    for (let i = 0; i < 300; i++) {
      const res = await request(app).get('/ftp/acquisitions.md')
      assert.equal(res.status, 200)
    }

    const throttledDownload = await request(app).get('/ftp/acquisitions.md')
    assert.equal(throttledDownload.status, 429)

    const spoofedClient = await request(app).get('/ftp/acquisitions.md').set('X-Forwarded-For', '10.13.37.1')
    assert.equal(spoofedClient.status, 429)

    for (const path of ['/ftp', '/ftp/quarantine/juicy_malware_linux_amd_64.url', '/encryptionkeys/jwt.pub', '/support/logs', '/.well-known/csaf/index.txt']) {
      const res = await request(app).get(path)
      assert.equal(res.status, 429, path)
    }

    const unrelated = await request(app).get('/rest/admin/application-version')
    assert.equal(unrelated.status, 200)
  })
})
