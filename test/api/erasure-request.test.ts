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

const bjoernOwasp = { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors', securityAnswer: 'Zaya' }

async function erasureSession () {
  const { token } = await login(app, bjoernOwasp)
  const form = await request(app)
    .get('/dataerasure/')
    .set({ Cookie: 'token=' + token })
  const csrf = /name="_csrf" value="([0-9a-f]+)"/.exec(form.text)?.[1]
  assert.ok(csrf, 'erasure form must contain an anti-forgery token')
  return { token, csrf }
}

async function deletionRequestCount () {
  const user = await UserModel.findOne({ where: { email: bjoernOwasp.email } })
  assert.ok(user)
  return await PrivacyRequestModel.count({ where: { UserId: user.id, deletionRequested: true } })
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

  void it('POST erasure request with confirmed email, security answer and anti-forgery token does not actually delete the user', async () => {
    const { token, csrf } = await erasureSession()

    const res = await request(app)
      .post('/dataerasure/')
      .type('form')
      .set({ Cookie: 'token=' + token })
      .send({ _csrf: csrf, email: bjoernOwasp.email, securityAnswer: bjoernOwasp.securityAnswer })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))

    const loginRes = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: bjoernOwasp.email, password: bjoernOwasp.password })

    assert.equal(loginRes.status, 200)
  })

  void it('POST erasure request with valid confirmation records a deletion request', async () => {
    const { token, csrf } = await erasureSession()
    const before = await deletionRequestCount()

    const res = await request(app)
      .post('/dataerasure/')
      .type('form')
      .set({ Cookie: 'token=' + token })
      .send({ _csrf: csrf, email: bjoernOwasp.email, securityAnswer: bjoernOwasp.securityAnswer })

    assert.equal(res.status, 200)
    assert.equal(await deletionRequestCount(), before + 1)
  })

  void it('POST erasure request without anti-forgery token is rejected and records nothing', async () => {
    const { token } = await erasureSession()
    const before = await deletionRequestCount()

    const res = await request(app)
      .post('/dataerasure/')
      .type('form')
      .set({ Cookie: 'token=' + token, Origin: 'https://attacker.example' })
      .send({ email: bjoernOwasp.email, securityAnswer: bjoernOwasp.securityAnswer })

    assert.equal(res.status, 403)
    assert.ok(res.text.includes('Invalid or missing anti-forgery token'))
    assert.equal(await deletionRequestCount(), before)
  })

  void it('POST erasure request with anti-forgery token of another session is rejected', async () => {
    const { token } = await erasureSession()
    const other = await login(app, { email: 'bjoern@juice-sh.op', password: 'monkey summer birthday are all bad passwords but work just fine in a long passphrase' })
    const otherForm = await request(app).get('/dataerasure/').set({ Cookie: 'token=' + other.token })
    const otherCsrf = /name="_csrf" value="([0-9a-f]+)"/.exec(otherForm.text)?.[1]
    assert.ok(otherCsrf)
    const before = await deletionRequestCount()

    const res = await request(app)
      .post('/dataerasure/')
      .type('form')
      .set({ Cookie: 'token=' + token })
      .send({ _csrf: otherCsrf, email: bjoernOwasp.email, securityAnswer: bjoernOwasp.securityAnswer })

    assert.equal(res.status, 403)
    assert.equal(await deletionRequestCount(), before)
  })

  void it('POST erasure request with wrong security answer is rejected and records nothing', async () => {
    const { token, csrf } = await erasureSession()
    const before = await deletionRequestCount()

    const res = await request(app)
      .post('/dataerasure/')
      .type('form')
      .set({ Cookie: 'token=' + token })
      .send({ _csrf: csrf, email: bjoernOwasp.email, securityAnswer: 'wrong' })

    assert.equal(res.status, 403)
    assert.ok(res.text.includes('Email address or security answer is incorrect'))
    assert.equal(await deletionRequestCount(), before)
  })

  void it('POST erasure request with mismatching email is rejected and records nothing', async () => {
    const { token, csrf } = await erasureSession()
    const before = await deletionRequestCount()

    const res = await request(app)
      .post('/dataerasure/')
      .type('form')
      .set({ Cookie: 'token=' + token })
      .send({ _csrf: csrf, email: 'admin@juice-sh.op', securityAnswer: bjoernOwasp.securityAnswer })

    assert.equal(res.status, 403)
    assert.equal(await deletionRequestCount(), before)
  })

  void it('POST erasure request fails for users without assigned security answer', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    const res = await request(app)
      .post('/dataerasure/')
      .type('form')
      .set({ Cookie: 'token=' + token })
      .send({ email: 'bjoern.kimminich@gmail.com', securityAnswer: 'anything' })

    assert.equal(res.status, 403)
  })

  void it('POST erasure form  fails on unauthenticated access', async () => {
    const res = await request(app)
      .post('/dataerasure/')

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST erasure request with empty layout parameter returns', async () => {
    const { token, csrf } = await erasureSession()

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ _csrf: csrf, email: bjoernOwasp.email, securityAnswer: bjoernOwasp.securityAnswer, layout: null })

    assert.equal(res.status, 200)
  })

  void it('POST erasure request with non-existing file path as layout parameter throws error', async () => {
    const { token, csrf } = await erasureSession()

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ _csrf: csrf, email: bjoernOwasp.email, securityAnswer: bjoernOwasp.securityAnswer, layout: '../this/file/does/not/exist' })

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('no such file or directory'))
  })

  void it('POST erasure request with existing file path as layout parameter returns content truncated', async () => {
    const { token, csrf } = await erasureSession()

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ _csrf: csrf, email: bjoernOwasp.email, securityAnswer: bjoernOwasp.securityAnswer, layout: '../package.json' })

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('juice-shop'))
    assert.ok(res.text.includes('......'))
  })
})
