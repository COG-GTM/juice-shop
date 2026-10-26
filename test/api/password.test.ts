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

void describe('/rest/user/change-password', () => {
  void it('GET password change for newly created user with recognized token as Authorization header', async () => {
    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'kuni@be.rt',
        password: 'kunigunde'
      })
      .expect(201)

    const { token } = await login(app, { email: 'kuni@be.rt', password: 'kunigunde' })

    const res = await request(app)
      .get('/rest/user/change-password?current=kunigunde&new=foo&repeat=foo')
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(res.status, 200)
  })

  void it('GET password change with passing wrong current password', async () => {
    const { token } = await login(app, {
      email: 'bjoern@' + config.get<string>('application.domain'),
      password: 'monkey summer birthday are all bad passwords but work just fine in a long passphrase'
    })

    const res = await request(app)
      .get('/rest/user/change-password?current=definetely_wrong&new=blubb&repeat=blubb')
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Current password is not correct'))
  })

  void it('GET password change without passing any passwords', async () => {
    const res = await request(app)
      .get('/rest/user/change-password')

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Password cannot be empty'))
  })

  void it('GET password change with passing wrong repeated password', async () => {
    const res = await request(app)
      .get('/rest/user/change-password?new=foo&repeat=bar')

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('New and repeated password do not match'))
  })

  void it('GET password change without passing an authorization token', async () => {
    const res = await request(app)
      .get('/rest/user/change-password?new=foo&repeat=foo')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('GET password change with passing unrecognized authorization token', async () => {
    const res = await request(app)
      .get('/rest/user/change-password?new=foo&repeat=foo')
      .set({ Authorization: 'Bearer unknown' })

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('GET password change for Bender without current password using GET request', async () => {
    const { token } = await login(app, {
      email: 'bender@' + config.get<string>('application.domain'),
      password: 'OhG0dPlease1nsertLiquor!'
    })

    const res = await request(app)
      .get('/rest/user/change-password?new=slurmCl4ssic&repeat=slurmCl4ssic')
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(res.status, 200)
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

void describe('/rest/user/reset-password brute-force protection', () => {
  const email = 'mc.safesearch@' + config.get<string>('application.domain')
  const wrongAnswer = (n: number) => request(app)
    .post('/rest/user/reset-password')
    .set({ 'content-type': 'application/json', 'X-Forwarded-For': `10.0.${Math.floor(n / 256)}.${n % 256}` })
    .send({ email, answer: 'wrong answer ' + n, new: 'p4ssw0rd!', repeat: 'p4ssw0rd!' })

  void it('locks the account after 10 wrong answers even when X-Forwarded-For rotates', async () => {
    for (let i = 0; i < 10; i++) {
      const res = await wrongAnswer(i)
      assert.equal(res.status, 401)
    }
    const res = await wrongAnswer(10)
    assert.equal(res.status, 429)
    assert.ok(Number(res.headers['retry-after']) > 0)
  })

  void it('rejects even the correct answer while the account is locked', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({ email: email.toUpperCase(), answer: 'I even shared my pizza bagels with you!', new: 'p4ssw0rd!', repeat: 'p4ssw0rd!' })

    assert.equal(res.status, 429)
  })

  void it('does not lock other accounts', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'amy@' + config.get<string>('application.domain'), answer: 'wrong', new: 'p4ssw0rd!', repeat: 'p4ssw0rd!' })

    assert.equal(res.status, 401)
  })
})

void describe('/rest/user/reset-password session revocation', () => {
  void it('invalidates tokens issued before the reset and accepts tokens issued after it', async () => {
    const email = 'revoke.me@' + config.get<string>('application.domain')
    const userRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ email, password: 'oldpassword' })
      .expect(201)
    await request(app)
      .post('/api/SecurityAnswers')
      .set({ 'content-type': 'application/json' })
      .send({ UserId: userRes.body.data.id, SecurityQuestionId: 1, answer: 'Revoked' })
      .expect(201)

    const { token: oldToken } = await login(app, { email, password: 'oldpassword' })
    await request(app).get('/api/Users').set({ Authorization: 'Bearer ' + oldToken }).expect(200)

    await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({ email, answer: 'Revoked', new: 'newpassword', repeat: 'newpassword' })
      .expect(200)

    const revoked = await request(app).get('/api/Users').set({ Authorization: 'Bearer ' + oldToken })
    assert.equal(revoked.status, 401)
    const whoami = await request(app).get('/rest/user/whoami').set({ Cookie: 'token=' + oldToken })
    assert.equal(whoami.body.user?.email, undefined)

    const { token: newToken } = await login(app, { email, password: 'newpassword' })
    await request(app).get('/api/Users').set({ Authorization: 'Bearer ' + newToken }).expect(200)
  })
})

void describe('/rest/user/reset-password client address rate limit', () => {
  void it('cannot be bypassed by rotating X-Forwarded-For', async () => {
    let res
    for (let i = 0; i < 101; i++) {
      res = await request(app)
        .post('/rest/user/reset-password')
        .set({ 'content-type': 'application/json', 'X-Forwarded-For': `172.16.${Math.floor(i / 256)}.${i % 256}` })
        .send({ email: `nobody${i}@` + config.get<string>('application.domain'), answer: 'guess', new: 'p4ssw0rd!', repeat: 'p4ssw0rd!' })
      if (res.status === 429) break
    }
    assert.equal(res?.status, 429)
  })
})
