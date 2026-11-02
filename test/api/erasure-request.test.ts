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

    assert.equal(res.status, 401)
    assert.equal(res.body.message, 'Session has ended. Please log in again.')
  })

  void it('POST erasure request does not actually delete the user', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .field('email', 'bjoern.kimminich@gmail.com')

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))

    const loginRes = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    assert.equal(loginRes.status, 200)
  })

  void it('POST erasure form  fails on unauthenticated access', async () => {
    const res = await request(app)
      .post('/dataerasure/')

    assert.equal(res.status, 401)
    assert.equal(res.body.message, 'Session has ended. Please log in again.')
  })

  void it('POST erasure request with empty layout parameter returns', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ layout: null })

    assert.equal(res.status, 200)
  })

  void it('POST erasure request with non-existing file path as layout parameter throws error', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ layout: '../this/file/does/not/exist' })

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('no such file or directory'))
  })

  void it('POST erasure request with existing file path as layout parameter returns content truncated', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ layout: '../package.json' })

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('juice-shop'))
    assert.ok(res.text.includes('......'))
  })

  void it('Erasure requests with a token replayed after a password change are rejected', async () => {
    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'erasure.replay@be.rt', password: 'kunigunde' })
      .expect(201)

    const { token: oldToken } = await login(app, { email: 'erasure.replay@be.rt', password: 'kunigunde' })
    const { token } = await login(app, { email: 'erasure.replay@be.rt', password: 'kunigunde' })

    await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + oldToken })
      .expect(200)

    await request(app)
      .get('/rest/user/change-password?current=kunigunde&new=foobar&repeat=foobar')
      .set({ Authorization: 'Bearer ' + token })
      .expect(200)

    const getRes = await request(app)
      .get('/dataerasure/')
      .set({ Cookie: 'token=' + oldToken })
    assert.equal(getRes.status, 401)

    const postRes = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + oldToken })
    assert.equal(postRes.status, 401)

    const exportRes = await request(app)
      .post('/rest/user/data-export')
      .set({ Authorization: 'Bearer ' + oldToken, 'content-type': 'application/json' })
      .send({ format: 1 })
    assert.equal(exportRes.status, 401)

    const changeRes = await request(app)
      .get('/rest/user/change-password?new=hijacked&repeat=hijacked')
      .set({ Authorization: 'Bearer ' + oldToken })
    assert.notEqual(changeRes.status, 200)
    await login(app, { email: 'erasure.replay@be.rt', password: 'foobar' })

    await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .expect(200)
  })

  void it('Erasure requests with a logged out token are rejected', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    await request(app)
      .post('/rest/user/logout')
      .set({ Authorization: 'Bearer ' + token, Cookie: 'token=' + token })
      .expect(204)

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
    assert.equal(res.status, 401)
  })
})
