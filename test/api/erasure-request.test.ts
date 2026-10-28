/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import fs from 'node:fs'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express

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

  void it('POST erasure request with confirmed email and security answer does not actually delete the user', async () => {
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .type('form')
      .send({ email: 'bjoern@owasp.org', securityAnswer: 'Zaya' })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('Sorry to see you leave!'))

    const loginRes = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    assert.equal(loginRes.status, 200)
  })

  void it('POST erasure form  fails on unauthenticated access', async () => {
    const res = await request(app)
      .post('/dataerasure/')

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST erasure request is rejected without a security answer', async () => {
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .type('form')
      .send({ email: 'bjoern@owasp.org' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Wrong answer to security question.'))
  })

  void it('POST erasure request is rejected with a wrong security answer', async () => {
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .type('form')
      .send({ email: 'bjoern@owasp.org', securityAnswer: 'Not Zaya' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Wrong answer to security question.'))
  })

  void it('POST erasure request is rejected when the email does not belong to the logged-in user', async () => {
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .type('form')
      .send({ email: 'admin@juice-sh.op', securityAnswer: 'Zaya' })

    assert.equal(res.status, 401)
  })

  void it('POST erasure request is rejected for users without assigned security answer', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .type('form')
      .send({ email: 'bjoern.kimminich@gmail.com', securityAnswer: 'anything' })

    assert.equal(res.status, 401)
  })

  void it('POST erasure request does not leak an existence oracle for a non-existing layout file', async () => {
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ email: 'bjoern@owasp.org', securityAnswer: 'Zaya', layout: '../this/file/does/not/exist' })

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('Sorry to see you leave!'))
    assert.ok(!res.text.includes('no such file or directory'))
  })

  void it('POST erasure request ignores an existing file passed as layout parameter', async () => {
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ email: 'bjoern@owasp.org', securityAnswer: 'Zaya', layout: '../package.json' })

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('Sorry to see you leave!'))
    assert.ok(!res.text.includes('"name": "juice-shop"'))
    assert.ok(!res.text.endsWith('......'))
  })

  void it('POST erasure request does not read the layout file even without a valid security answer', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .type('form')
      .send({ layout: '../package.json' })

    assert.equal(res.status, 401)
    assert.ok(!res.text.includes('"name": "juice-shop"'))
  })

  void it('POST erasure request does not pass request body fields or view settings to the template', async () => {
    const ctfKey = fs.readFileSync('ctf.key', 'utf8').trim()
    const payloads = [
      { _title_: 'injected-title-marker', settings: { 'view options': { layout: '../package.json' } } },
      { layout: 'ctf.key', settings: { views: process.cwd() } },
      'layout=.&settings[views]=ctf.key',
      'settings[views]=.&settings[view options][layout]=ctf.key'
    ]
    for (const payload of payloads) {
      const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })
      const confirmation = 'email=bjoern%40owasp.org&securityAnswer=Zaya'

      const res = typeof payload === 'string'
        ? await request(app).post('/dataerasure/').set({ Cookie: 'token=' + token }).type('form').send(`${confirmation}&${payload}`)
        : await request(app).post('/dataerasure/').set({ Cookie: 'token=' + token }).send({ email: 'bjoern@owasp.org', securityAnswer: 'Zaya', ...payload })

      assert.equal(res.status, 200)
      assert.ok(res.text.includes('Sorry to see you leave!'))
      assert.ok(!res.text.includes('injected-title-marker'))
      assert.ok(!res.text.includes('"name": "juice-shop"'))
      assert.ok(!res.text.includes(ctfKey))
    }
  })
})
