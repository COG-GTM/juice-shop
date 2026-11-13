/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import http from 'node:http'
import assert from 'node:assert/strict'
import request from 'supertest'
import { createTestApp } from './helpers/setup'

let server: http.Server

before(async () => {
  const { app } = await createTestApp()
  server = http.createServer(app).listen(0)
}, { timeout: 60000 })

after(() => {
  server.close()
})

void describe('File serving rate limit', () => {
  void it('GET /ftp/legal.md exposes rate limit headers', async () => {
    const res = await request(server).get('/ftp/legal.md')
    assert.equal(res.status, 200)
    assert.ok(res.headers.ratelimit?.includes('limit=300'))
    assert.ok(res.headers['ratelimit-policy']?.includes('300;w=60'))
  })

  void it('GET on file serving routes is rejected with 429 once 300 requests per minute are exceeded', async () => {
    const paths = ['/ftp/legal.md', '/.well-known/csaf/provider-metadata.json', '/encryptionkeys/jwt.pub', '/support/logs']
    let remaining = Infinity
    for (let i = 0; remaining > 0; i++) {
      assert.ok(i < 300, 'rate limit allowed more than 300 requests')
      const res = await request(server).get(paths[i % paths.length])
      assert.notEqual(res.status, 429, `request to ${paths[i % paths.length]} was rate limited with ${remaining} requests remaining`)
      remaining = Number(/remaining=(\d+)/.exec(res.headers.ratelimit ?? '')?.[1])
    }
    for (const path of paths) {
      const res = await request(server).get(path)
      assert.equal(res.status, 429, `${path} was not rate limited`)
      assert.ok(res.headers['retry-after'])
    }
  })

  void it('GET on routes without file serving is not rate limited', async () => {
    const res = await request(server).get('/rest/admin/application-version')
    assert.equal(res.status, 200)
  })
})
