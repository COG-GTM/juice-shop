/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { loadStaticUserData } from '../../data/staticData'
import { challenges } from '../../data/datacache'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const domain = config.get<string>('application.domain')

const credentialChallenges = [
  { userKey: 'admin', challengeKey: 'weakPasswordChallenge' },
  { userKey: 'support', challengeKey: 'loginSupportChallenge' },
  { userKey: 'rapper', challengeKey: 'loginRapperChallenge' },
  { userKey: 'amy', challengeKey: 'loginAmyChallenge' },
  { userKey: 'jannik', challengeKey: 'dlpPasswordSprayingChallenge' },
  { userKey: 'bjoernGoogle', challengeKey: 'oauthUserPasswordChallenge' },
  { userKey: 'LetUsTest', challengeKey: 'exposedCredentialsChallenge' }
] as const

async function seedCredentialsOf (userKey: string) {
  const user = (await loadStaticUserData()).find(({ key }) => key === userKey)
  assert.ok(user, `${userKey} missing from users.yml`)
  return { email: user.customDomain ? user.email : `${user.email}@${domain}`, password: user.password }
}

async function login (email: string, password: string) {
  return await request(app)
    .post('/rest/user/login')
    .set({ 'content-type': 'application/json' })
    .send({ email, password })
}

void describe('pre-login credential challenges', () => {
  void it('routes/login.ts does not contain the password of any seeded account', async () => {
    const source = await fs.readFile(path.resolve('routes/login.ts'), 'utf8')
    for (const { email, password } of await loadStaticUserData()) {
      for (const quote of ['\'', '"', '`']) {
        assert.ok(!source.includes(`${quote}${password}${quote}`), `routes/login.ts contains the seed password of ${email}`)
      }
    }
  })

  for (const { userKey, challengeKey } of credentialChallenges) {
    void it(`does not solve ${challengeKey} with a wrong password for the ${userKey} account`, async () => {
      const { email, password } = await seedCredentialsOf(userKey)
      await login(email, `${password}x`)
      assert.equal(challenges[challengeKey].solved, false)
    })

    void it(`does not solve ${challengeKey} with the ${userKey} password for another account`, async () => {
      const { password } = await seedCredentialsOf(userKey)
      await login(`jim@${domain}`, password)
      assert.equal(challenges[challengeKey].solved, false)
    })

    void it(`solves ${challengeKey} with the seeded ${userKey} credentials`, async () => {
      const { email, password } = await seedCredentialsOf(userKey)
      await login(email, password)
      assert.equal(challenges[challengeKey].solved, true)
    })
  }

  void it('ignores non-string email and password values', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: [`amy@${domain}`], password: { toString: 'x' } })
    assert.notEqual(res.status, 200)
  })
})
