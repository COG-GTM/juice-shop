/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

const adminToken = security.authorize({ data: { id: 1, email: 'admin@juice-sh.op', role: security.roles.admin } })
const customerToken = security.authorize({ data: { id: 2, email: 'jim@juice-sh.op', role: security.roles.customer } })

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/encryptionkeys', () => {
  void it('GET directory listing anonymously is rejected', async () => {
    const res = await request(app).get('/encryptionkeys')
    assert.equal(res.status, 403)
  })

  void it('GET key file anonymously is rejected', async () => {
    const res = await request(app).get('/encryptionkeys/jwt.pub')
    assert.equal(res.status, 403)
  })

  void it('GET key file as customer is rejected', async () => {
    const res = await request(app)
      .get('/encryptionkeys/jwt.pub')
      .set({ Authorization: `Bearer ${customerToken}` })
    assert.equal(res.status, 403)
  })

  void it('GET key file as admin succeeds', async () => {
    const res = await request(app)
      .get('/encryptionkeys/jwt.pub')
      .set({ Authorization: `Bearer ${adminToken}` })
    assert.equal(res.status, 200)
  })

  void it('GET key file as admin authenticated through the session cookie succeeds', async () => {
    const res = await request(app)
      .get('/encryptionkeys/jwt.pub')
      .set({ Cookie: `token=${adminToken}` })
    assert.equal(res.status, 200)
  })

  void it('GET key file with an invalid token is rejected', async () => {
    const res = await request(app)
      .get('/encryptionkeys/jwt.pub')
      .set({ Authorization: 'Bearer InvalidAuthToken' })
    assert.equal(res.status, 403)
  })

  void it('GET key file outside the keys directory is rejected', async () => {
    const res = await request(app)
      .get('/encryptionkeys/%2e%2e%2fpackage.json')
      .set({ Authorization: `Bearer ${adminToken}` })
    assert.equal(res.status, 403)
  })
})

void describe('/support/logs', () => {
  void it('GET directory listing anonymously is rejected', async () => {
    const res = await request(app).get('/support/logs')
    assert.equal(res.status, 403)
  })

  void it('GET log file as customer is rejected', async () => {
    const res = await request(app)
      .get('/support/logs/access.log')
      .set({ Authorization: `Bearer ${customerToken}` })
    assert.equal(res.status, 403)
  })

  void it('GET directory listing as admin succeeds', async () => {
    const res = await request(app)
      .get('/support/logs')
      .set({ Authorization: `Bearer ${adminToken}` })
    assert.equal(res.status, 200)
  })

  void it('GET log file outside the logs directory is rejected', async () => {
    const res = await request(app)
      .get('/support/logs/%2e%2e%2fpackage.json')
      .set({ Authorization: `Bearer ${adminToken}` })
    assert.equal(res.status, 403)
  })
})
