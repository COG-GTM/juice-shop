/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/api/Hints/:id', () => {
  void it('PUT unlocking a hint is allowed without authentication', async () => {
    const res = await request(app)
      .put('/api/Hints/1')
      .set('content-type', 'application/json')
      .send({ unlocked: true })

    assert.equal(res.status, 200)
    assert.equal(res.body.data.unlocked, true)
  })

  void it('PUT changing hint text is forbidden without authentication', async () => {
    const res = await request(app)
      .put('/api/Hints/1')
      .set('content-type', 'application/json')
      .send({ text: 'Tampered hint' })

    assert.equal(res.status, 403)
  })

  void it('PUT changing hint text alongside unlocking is forbidden without authentication', async () => {
    const res = await request(app)
      .put('/api/Hints/1')
      .set('content-type', 'application/json')
      .send({ unlocked: true, text: 'Tampered hint' })

    assert.equal(res.status, 403)
  })

  void it('PUT re-locking a hint is forbidden without authentication', async () => {
    const res = await request(app)
      .put('/api/Hints/1')
      .set('content-type', 'application/json')
      .send({ unlocked: false })

    assert.equal(res.status, 403)
  })

  void it('PUT changing hint text is forbidden for customers', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })
    const res = await request(app)
      .put('/api/Hints/1')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({ text: 'Tampered hint' })

    assert.equal(res.status, 403)
  })

  void it('PUT changing hint text is allowed for admins', async () => {
    const { token } = await login(app, {
      email: `admin@${config.get<string>('application.domain')}`,
      password: 'admin123'
    })
    const res = await request(app)
      .put('/api/Hints/2')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({ text: 'Updated by admin' })

    assert.equal(res.status, 200)
    assert.equal(res.body.data.text, 'Updated by admin')
  })
})
