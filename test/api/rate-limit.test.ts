/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http, { type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import request from 'supertest'
import { createTestApp } from './helpers/setup'

const requestsPerWindow = 1000

let server: Server

before(async () => {
  const { app } = await createTestApp()
  server = app.listen(0)
  for (let i = 0; i < requestsPerWindow; i++) {
    const res = await request(server).get('/rest/2fa/status')
    assert.equal(res.status, 401, 'authorization-checked route must answer normally below the per-client ceiling')
  }
}, { timeout: 120000 })

after(() => {
  server.close()
})

void describe('API rate limiting', () => {
  void it('rejects further requests from the same client with 429', async () => {
    const res = await request(server).get('/rest/2fa/status')
    assert.equal(res.status, 429)
    const profile = await request(server).get('/profile')
    assert.equal(profile.status, 429)
  })

  void it('cannot be bypassed by spoofing X-Forwarded-For', async () => {
    const res = await request(server)
      .get('/rest/2fa/status')
      .set('X-Forwarded-For', '203.0.113.7')
    assert.equal(res.status, 429)
  })

  void it('keeps a separate allowance for a different client address', { skip: process.platform === 'darwin' && '127.0.0.2 is not a loopback address on macOS' }, async () => {
    const status = await new Promise<number | undefined>((resolve, reject) => {
      http.get({
        host: '127.0.0.1',
        port: (server.address() as AddressInfo).port,
        path: '/rest/2fa/status',
        localAddress: '127.0.0.2'
      }, res => {
        res.resume()
        resolve(res.statusCode)
      }).on('error', reject)
    })
    assert.equal(status, 401)
  })
})
