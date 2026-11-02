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
import { PrivacyRequestModel } from '../../models/privacyRequests'
import { UserModel } from '../../models/user'

let app: Express

const bjoern = { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' }
const bjoernConfirmation = { email: 'bjoern@owasp.org', securityAnswer: 'Zaya' }

async function deletionRequestCount (email: string) {
  const user = await UserModel.findOne({ where: { email } })
  return await PrivacyRequestModel.count({ where: { UserId: user?.id, deletionRequested: true } })
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/dataerasure', () => {
  void it('GET erasure form for logged-in users includes their email and security question', async () => {
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    const res = await request(app)
      .get('/dataerasure/')
      .set({ Cookie: 'token=' + token })

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('bjoern@owasp.org'))
    assert.ok(res.text.includes('Name of your favorite pet?'))
  })

  void it('GET erasure form rendering fails for users without assigned security answer', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    const res = await request(app)
      .get('/dataerasure/')
      .set({ Cookie: 'token=' + token })

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: No answer found!'))
  })

  void it('GET erasure form rendering fails on unauthenticated access', async () => {
    const res = await request(app)
      .get('/dataerasure/')

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST erasure request does not actually delete the user', async () => {
    const { token } = await login(app, bjoern)

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .type('form')
      .send(bjoernConfirmation)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))

    const loginRes = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send(bjoern)

    assert.equal(loginRes.status, 200)
  })

  void it('POST erasure request with correct email and security answer files a deletion request', async () => {
    const { token } = await login(app, bjoern)
    const before = await deletionRequestCount(bjoern.email)

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .type('form')
      .send({ email: ' Bjoern@OWASP.org ', securityAnswer: 'Zaya' })

    assert.equal(res.status, 200)
    assert.equal(await deletionRequestCount(bjoern.email), before + 1)
  })

  void it('POST erasure request with wrong security answer is rejected without filing a deletion request', async () => {
    const { token } = await login(app, bjoern)
    const before = await deletionRequestCount(bjoern.email)

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .type('form')
      .send({ email: bjoern.email, securityAnswer: 'Not Zaya' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Wrong answer to security question.'))
    assert.equal(res.headers['set-cookie'], undefined)
    assert.equal(await deletionRequestCount(bjoern.email), before)
  })

  void it('POST erasure request without email and security answer is rejected without filing a deletion request', async () => {
    const { token } = await login(app, bjoern)
    const before = await deletionRequestCount(bjoern.email)

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })

    assert.equal(res.status, 401)
    assert.equal(await deletionRequestCount(bjoern.email), before)
  })

  void it('POST erasure request with another user\'s email is rejected without filing a deletion request', async () => {
    const { token } = await login(app, bjoern)
    const before = await deletionRequestCount(bjoern.email)

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .type('form')
      .send({ email: 'jim@juice-sh.op', securityAnswer: 'Zaya' })

    assert.equal(res.status, 401)
    assert.equal(await deletionRequestCount(bjoern.email), before)
  })

  void it('POST erasure request with non-string security answer is rejected', async () => {
    const { token } = await login(app, bjoern)

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ email: bjoern.email, securityAnswer: ['Zaya'] })

    assert.equal(res.status, 401)
  })

  void it('POST erasure request is rejected for users without a security answer', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .type('form')
      .send({ email: 'bjoern.kimminich@gmail.com', securityAnswer: '' })

    assert.equal(res.status, 401)
    assert.equal(await deletionRequestCount('bjoern.kimminich@gmail.com'), 0)
  })

  void it('POST erasure form  fails on unauthenticated access', async () => {
    const res = await request(app)
      .post('/dataerasure/')

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST erasure request with empty layout parameter returns', async () => {
    const { token } = await login(app, bjoern)

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ ...bjoernConfirmation, layout: null })

    assert.equal(res.status, 200)
  })

  void it('POST erasure request with non-existing file path as layout parameter throws error', async () => {
    const { token } = await login(app, bjoern)

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ ...bjoernConfirmation, layout: '../this/file/does/not/exist' })

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('no such file or directory'))
  })

  void it('POST erasure request with existing file path as layout parameter returns content truncated', async () => {
    const { token } = await login(app, bjoern)

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ ...bjoernConfirmation, layout: '../package.json' })

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('juice-shop'))
    assert.ok(res.text.includes('......'))
  })
})
