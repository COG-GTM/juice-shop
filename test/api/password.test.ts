/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, mock } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const jsonHeader = { 'content-type': 'application/json' }

async function loginStatus (email: string, password: string) {
  const res = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })
  return res.status
}

void describe('/rest/user/change-password', () => {
  void it('POST password change for newly created user with recognized token as Authorization header', async () => {
    await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'kuni@be.rt',
        password: 'kunigunde'
      })
      .expect(201)

    const { token } = await login(app, { email: 'kuni@be.rt', password: 'kunigunde' })

    const res = await request(app)
      .post('/rest/user/change-password')
      .set({ ...jsonHeader, Authorization: 'Bearer ' + token })
      .send({ current: 'kunigunde', new: 'foo', repeat: 'foo' })

    assert.equal(res.status, 200)
    assert.deepEqual(Object.keys(res.body.user).sort(), ['email', 'id', 'username'])
    assert.equal(res.body.user.email, 'kuni@be.rt')
    assert.ok(!res.text.includes('totpSecret'))
    assert.ok(!res.text.includes('password'))
    assert.equal(await loginStatus('kuni@be.rt', 'foo'), 200)
  })

  void it('POST password change with passing wrong current password', async () => {
    const { token } = await login(app, {
      email: 'bjoern@' + config.get<string>('application.domain'),
      password: 'monkey summer birthday are all bad passwords but work just fine in a long passphrase'
    })

    const res = await request(app)
      .post('/rest/user/change-password')
      .set({ ...jsonHeader, Authorization: 'Bearer ' + token })
      .send({ current: 'definetely_wrong', new: 'blubb', repeat: 'blubb' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Current password is not correct'))
  })

  void it('POST password change with valid token but without current password is rejected and leaves password unchanged', async () => {
    await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'nocurrent@be.rt',
        password: 'original-secret'
      })
      .expect(201)

    const { token } = await login(app, { email: 'nocurrent@be.rt', password: 'original-secret' })

    for (const current of [undefined, '', ['original-secret']]) {
      const res = await request(app)
        .post('/rest/user/change-password')
        .set({ ...jsonHeader, Authorization: 'Bearer ' + token })
        .send({ current, new: 'hijacked', repeat: 'hijacked' })

      assert.equal(res.status, 401)
      assert.ok(res.text.includes('Current password is not correct'))
    }

    assert.equal(await loginStatus('nocurrent@be.rt', 'original-secret'), 200)
    assert.equal(await loginStatus('nocurrent@be.rt', 'hijacked'), 401)
  })

  void it('POST password change from a second session with the superseded password is rejected', async () => {
    await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'twosessions@be.rt',
        password: 'first-secret'
      })
      .expect(201)

    const { token: tokenA } = await login(app, { email: 'twosessions@be.rt', password: 'first-secret' })
    const { token: tokenB } = await login(app, { email: 'twosessions@be.rt', password: 'first-secret' })

    await request(app)
      .post('/rest/user/change-password')
      .set({ ...jsonHeader, Authorization: 'Bearer ' + tokenA })
      .send({ current: 'first-secret', new: 'second-secret', repeat: 'second-secret' })
      .expect(200)

    const res = await request(app)
      .post('/rest/user/change-password')
      .set({ ...jsonHeader, Authorization: 'Bearer ' + tokenB })
      .send({ current: 'first-secret', new: 'hijacked', repeat: 'hijacked' })

    assert.equal(res.status, 401)
    assert.equal(await loginStatus('twosessions@be.rt', 'second-secret'), 200)
    assert.equal(await loginStatus('twosessions@be.rt', 'hijacked'), 401)
  })

  void it('POST concurrent password changes from two sessions let exactly one succeed', async () => {
    await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'concurrent@be.rt',
        password: 'shared-secret'
      })
      .expect(201)

    const { token: tokenA } = await login(app, { email: 'concurrent@be.rt', password: 'shared-secret' })
    await new Promise(resolve => setTimeout(resolve, 1100))
    const { token: tokenB } = await login(app, { email: 'concurrent@be.rt', password: 'shared-secret' })
    assert.notEqual(tokenA, tokenB)

    const [resA, resB] = await Promise.all([
      request(app)
        .post('/rest/user/change-password')
        .set({ ...jsonHeader, Authorization: 'Bearer ' + tokenA })
        .send({ current: 'shared-secret', new: 'alpha-secret', repeat: 'alpha-secret' }),
      request(app)
        .post('/rest/user/change-password')
        .set({ ...jsonHeader, Authorization: 'Bearer ' + tokenB })
        .send({ current: 'shared-secret', new: 'beta-secret', repeat: 'beta-secret' })
    ])

    const statuses = [resA.status, resB.status].sort()
    assert.deepEqual(statuses, [200, 401])
    const winner = resA.status === 200 ? { token: tokenA, password: 'alpha-secret' } : { token: tokenB, password: 'beta-secret' }
    const loser = resA.status === 200 ? 'beta-secret' : 'alpha-secret'
    assert.equal(await loginStatus('concurrent@be.rt', winner.password), 200)
    assert.equal(await loginStatus('concurrent@be.rt', loser), 401)
    await request(app)
      .get('/rest/2fa/status')
      .set({ Authorization: 'Bearer ' + winner.token })
      .expect(200)
  })

  void it('POST password change revokes all other sessions of the user but keeps the current one', async () => {
    await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'revoke@be.rt',
        password: 'before-change'
      })
      .expect(201)

    const { token: stolenToken } = await login(app, { email: 'revoke@be.rt', password: 'before-change' })
    await new Promise(resolve => setTimeout(resolve, 1100))
    const { token: ownerToken } = await login(app, { email: 'revoke@be.rt', password: 'before-change' })
    assert.notEqual(stolenToken, ownerToken)

    await request(app)
      .post('/rest/user/change-password')
      .set({ ...jsonHeader, Authorization: 'Bearer ' + ownerToken })
      .send({ current: 'before-change', new: 'after-change', repeat: 'after-change' })
      .expect(200)

    await request(app)
      .get('/rest/2fa/status')
      .set({ Authorization: 'Bearer ' + stolenToken })
      .expect(401)
    await request(app)
      .get('/rest/2fa/status')
      .set({ Authorization: 'Bearer ' + ownerToken })
      .expect(200)

    const res = await request(app)
      .post('/rest/user/change-password')
      .set({ ...jsonHeader, Authorization: 'Bearer ' + stolenToken })
      .send({ current: 'after-change', new: 'hijacked', repeat: 'hijacked' })
    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
    assert.equal(await loginStatus('revoke@be.rt', 'after-change'), 200)
  })

  void it('POST password change with an expired token is rejected and leaves password unchanged', async () => {
    await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'expired@be.rt',
        password: 'original-secret'
      })
      .expect(201)

    const { token } = await login(app, { email: 'expired@be.rt', password: 'original-secret' })

    mock.timers.enable({ apis: ['Date'], now: Date.now() + 6 * 60 * 60 * 1000 + 60 * 1000 })
    try {
      const res = await request(app)
        .post('/rest/user/change-password')
        .set({ ...jsonHeader, Authorization: 'Bearer ' + token })
        .send({ current: 'original-secret', new: 'hijacked', repeat: 'hijacked' })
      assert.equal(res.status, 401)
      assert.ok(res.text.includes('Error: Blocked illegal activity'))
    } finally {
      mock.timers.reset()
    }

    assert.equal(await loginStatus('expired@be.rt', 'original-secret'), 200)
    assert.equal(await loginStatus('expired@be.rt', 'hijacked'), 401)
  })

  void it('POST password change with a token not signed by the server is rejected', async () => {
    await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'forged@be.rt',
        password: 'original-secret'
      })
      .expect(201)

    const { token } = await login(app, { email: 'forged@be.rt', password: 'original-secret' })
    const [header, payload] = token.split('.')
    const forged = `${header}.${payload}.${Buffer.from('forged').toString('base64url')}`
    security.authenticatedUsers.put(forged, security.authenticatedUsers.get(token)!)

    const res = await request(app)
      .post('/rest/user/change-password')
      .set({ ...jsonHeader, Authorization: 'Bearer ' + forged })
      .send({ current: 'original-secret', new: 'hijacked', repeat: 'hijacked' })

    assert.equal(res.status, 401)
    assert.equal(await loginStatus('forged@be.rt', 'original-secret'), 200)
  })

  void it('GET password change via query string is no longer supported', async () => {
    await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'viaget@be.rt',
        password: 'original-secret'
      })
      .expect(201)

    const { token } = await login(app, { email: 'viaget@be.rt', password: 'original-secret' })

    await request(app)
      .get('/rest/user/change-password?current=original-secret&new=changed&repeat=changed')
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(await loginStatus('viaget@be.rt', 'original-secret'), 200)
    assert.equal(await loginStatus('viaget@be.rt', 'changed'), 401)
  })

  void it('POST password change without passing any passwords', async () => {
    const res = await request(app)
      .post('/rest/user/change-password')
      .set(jsonHeader)
      .send({})

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Password cannot be empty'))
  })

  void it('POST password change with passing wrong repeated password', async () => {
    const res = await request(app)
      .post('/rest/user/change-password')
      .set(jsonHeader)
      .send({ new: 'foo', repeat: 'bar' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('New and repeated password do not match'))
  })

  void it('POST password change without passing an authorization token', async () => {
    const res = await request(app)
      .post('/rest/user/change-password')
      .set(jsonHeader)
      .send({ new: 'foo', repeat: 'foo' })

    assert.equal(res.status, 401)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST password change with passing unrecognized authorization token', async () => {
    const res = await request(app)
      .post('/rest/user/change-password')
      .set({ ...jsonHeader, Authorization: 'Bearer unknown' })
      .send({ new: 'foo', repeat: 'foo' })

    assert.equal(res.status, 401)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST password change for Bender without current password is rejected', async () => {
    const { token } = await login(app, {
      email: 'bender@' + config.get<string>('application.domain'),
      password: 'OhG0dPlease1nsertLiquor!'
    })

    const res = await request(app)
      .post('/rest/user/change-password')
      .set({ ...jsonHeader, Authorization: 'Bearer ' + token })
      .send({ new: 'slurmCl4ssic', repeat: 'slurmCl4ssic' })

    assert.equal(res.status, 401)
    assert.equal(await loginStatus('bender@' + config.get<string>('application.domain'), 'OhG0dPlease1nsertLiquor!'), 200)
  })
})

void describe('/rest/user/reset-password', () => {
  void it('POST password reset for Jim with correct answer to his security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'jim@' + config.get<string>('application.domain'),
        answer: 'Samuel',
        new: 'ncc-1701',
        repeat: 'ncc-1701'
      })

    assert.equal(res.status, 200)
  })

  void it('POST password reset for Bender with correct answer to his security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bender@' + config.get<string>('application.domain'),
        answer: 'Stop\'n\'Drop',
        new: 'OhG0dPlease1nsertLiquor!',
        repeat: 'OhG0dPlease1nsertLiquor!'
      })

    assert.equal(res.status, 200)
  })

  void it('POST password reset for Bjoern\u00b4s internal account with correct answer to his security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        answer: 'West-2082',
        new: 'monkey summer birthday are all bad passwords but work just fine in a long passphrase',
        repeat: 'monkey summer birthday are all bad passwords but work just fine in a long passphrase'
      })

    assert.equal(res.status, 200)
  })

  void it('POST password reset for Bjoern\u00b4s OWASP account with correct answer to his security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@owasp.org',
        answer: 'Zaya',
        new: 'kitten lesser pooch karate buffoon indoors',
        repeat: 'kitten lesser pooch karate buffoon indoors'
      })

    assert.equal(res.status, 200)
  })

  void it('POST password reset for Morty with correct answer to his security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'morty@' + config.get<string>('application.domain'),
        answer: '5N0wb41L',
        new: 'iBurri3dMySe1fInTheB4ckyard!',
        repeat: 'iBurri3dMySe1fInTheB4ckyard!'
      })

    assert.equal(res.status, 200)
  })

  void it('POST password reset with wrong answer to security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        answer: '25436',
        new: '12345',
        repeat: '12345'
      })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Wrong answer to security question.'))
  })

  void it('POST password reset without any data is blocked', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST password reset without new password throws a 401 error', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        answer: 'W-2082',
        repeat: '12345'
      })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Password cannot be empty.'))
  })

  void it('POST password reset with mismatching passwords throws a 401 error', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        answer: 'W-2082',
        new: '12345',
        repeat: '1234_'
      })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('New and repeated password do not match.'))
  })

  void it('POST password reset with no email address throws a 412 error', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        answer: 'W-2082',
        new: 'abcdef',
        repeat: 'abcdef'
      })

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST password reset with no answer to the security question throws a 412 error', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        new: 'abcdef',
        repeat: 'abcdef'
      })

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })
})
