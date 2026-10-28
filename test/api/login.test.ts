/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Sequelize } from 'sequelize'
import config from 'config'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

let app: Express
let sequelize: Sequelize

before(async () => {
  const result = await createTestApp()
  app = result.app
  sequelize = result.sequelize
}, { timeout: 60000 })

async function storedPasswordOf (email: string) {
  const [rows] = await sequelize.query('SELECT password FROM Users WHERE email = ?', { replacements: [email] })
  return (rows as Array<{ password: string }>)[0].password
}

void describe('/rest/user/login', () => {
  void it('POST login newly created user', async () => {
    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'kalli@kasper.le',
        password: 'kallliiii'
      })
      .expect(201)

    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'kalli@kasper.le',
        password: 'kallliiii'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
    assert.equal(typeof res.body.authentication.umail, 'string')
    assert.equal(typeof res.body.authentication.bid, 'number')
  })

  void it('POST login non-existing user', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'otto@mei.er',
        password: 'ooootto'
      })

    assert.equal(res.status, 401)
  })

  void it('POST login without credentials', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: undefined,
        password: undefined
      })

    assert.equal(res.status, 401)
  })

  void it('POST login with admin credentials', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'admin@' + config.get<string>('application.domain'),
        password: 'admin123'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with support-team credentials', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'support@' + config.get<string>('application.domain'),
        password: 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with MC SafeSearch credentials', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'mc.safesearch@' + config.get<string>('application.domain'),
        password: 'Mr. N00dles'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with Amy credentials', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'amy@' + config.get<string>('application.domain'),
        password: 'K1f.....................'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with wurstbrot credentials expects 2FA token', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'wurstbrot@' + config.get<string>('application.domain'),
        password: 'EinBelegtesBrotMitSchinkenSCHINKEN!'
      })

    assert.equal(res.status, 401)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.tmpToken, 'string')
    assert.equal(res.body.status, 'totp_token_required')
  })

  void it('POST login as bjoern.kimminich@gmail.com with known password', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern.kimminich@gmail.com',
        password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with WHERE-clause disabling SQL injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: '\' or 1=1--',
        password: undefined
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with known email "admin@juice-sh.op" in SQL injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'admin@' + config.get<string>('application.domain') + '\'--',
        password: undefined
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with known email "jim@juice-sh.op" in SQL injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'jim@' + config.get<string>('application.domain') + '\'--',
        password: undefined
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with known email "bender@juice-sh.op" in SQL injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bender@' + config.get<string>('application.domain') + '\'--',
        password: undefined
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with non-existing email "acc0unt4nt@juice-sh.op" via UNION SELECT injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: `' UNION SELECT * FROM (SELECT 15 as 'id', '' as 'username', 'acc0unt4nt@${config.get<string>('application.domain')}' as 'email', '12345' as 'password', 'accounting' as 'role', '' as deluxeToken, '1.2.3.4' as 'lastLoginIp' , '/assets/public/images/uploads/default.svg' as 'profileImage', '' as 'totpSecret', 1 as 'isActive', '1999-08-16 14:14:41.644 +00:00' as 'createdAt', '1999-08-16 14:33:41.930 +00:00' as 'updatedAt', null as 'deletedAt')--`,
        password: undefined
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with query-breaking SQL Injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: '\';',
        password: undefined
      })

    assert.equal(res.status, 401)
  })
})

void describe('/rest/saveLoginIp', () => {
  void it('GET last login IP will be saved as True-Client-IP header value', async () => {
    const loginRes = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern.kimminich@gmail.com',
        password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
      })

    assert.equal(loginRes.status, 200)

    const res = await request(app)
      .get('/rest/saveLoginIp')
      .set({
        Authorization: 'Bearer ' + loginRes.body.authentication.token,
        'true-client-ip': '1.2.3.4'
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.lastLoginIp, '1.2.3.4')
  })

  void it('GET last login IP will be saved as remote IP when True-Client-IP is not present', { skip: 'FIXME Started to fail regularly on CI under Linux' }, async () => {
    const loginRes = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern.kimminich@gmail.com',
        password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
      })

    assert.equal(loginRes.status, 200)

    const res = await request(app)
      .get('/rest/saveLoginIp')
      .set({
        Authorization: 'Bearer ' + loginRes.body.authentication.token
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.lastLoginIp, '127.0.0.1')
  })
})

void describe('password storage', () => {
  void it('stores salted scrypt hashes so equal passwords get different stored values', async () => {
    for (const email of ['salt.one@juice-sh.op', 'salt.two@juice-sh.op']) {
      await request(app)
        .post('/api/Users')
        .set({ 'content-type': 'application/json' })
        .send({ email, password: 'SamePassw0rd!' })
        .expect(201)
    }

    const first = await storedPasswordOf('salt.one@juice-sh.op')
    const second = await storedPasswordOf('salt.two@juice-sh.op')
    assert.match(first, /^scrypt\$16384\$8\$5\$/)
    assert.match(second, /^scrypt\$16384\$8\$5\$/)
    assert.notEqual(first, second)
    assert.notEqual(first, security.hash('SamePassw0rd!'))

    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'salt.two@juice-sh.op', password: 'SamePassw0rd!' })
    assert.equal(res.status, 200)
  })

  void it('upgrades a legacy unsalted MD5 hash on the next successful login', async () => {
    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'legacy.md5@juice-sh.op', password: 'legacyPassw0rd' })
      .expect(201)
    await sequelize.query('UPDATE Users SET password = ? WHERE email = ?', { replacements: [security.hash('legacyPassw0rd'), 'legacy.md5@juice-sh.op'] })

    const wrong = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'legacy.md5@juice-sh.op', password: 'wrongPassw0rd' })
    assert.equal(wrong.status, 401)
    assert.equal(await storedPasswordOf('legacy.md5@juice-sh.op'), security.hash('legacyPassw0rd'))

    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'legacy.md5@juice-sh.op', password: 'legacyPassw0rd' })
    assert.equal(res.status, 200)

    const upgraded = await storedPasswordOf('legacy.md5@juice-sh.op')
    assert.match(upgraded, /^scrypt\$16384\$8\$5\$/)
    assert.equal(await security.verifyPassword('legacyPassw0rd', upgraded), true)
  })
})
