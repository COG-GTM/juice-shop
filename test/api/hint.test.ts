/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

let app: Express
const authHeader = { Authorization: `Bearer ${security.authorize()}`, 'content-type': 'application/json' }
const jsonHeader = { 'content-type': 'application/json' }

const germanCatalog = path.resolve('data/static/i18n/de_DE.json')
const englishHint = 'Hints to the answer to Bjoern\u2019s question can be found by looking him up on the Internet.'
const germanHint: string = JSON.parse(fs.readFileSync(germanCatalog, 'utf8'))[englishHint]

before(async () => {
  // the backend i18n catalogs are copied over from data/static on server startup only
  fs.copyFileSync(germanCatalog, path.resolve('i18n/de_DE.json'))
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function firstHintId (): Promise<number> {
  const res = await request(app).get('/api/Hints')
  return res.body.data[0].id
}

void describe('/api/Hints', () => {
  void it('GET all hints', async () => {
    const res = await request(app)
      .get('/api/Hints')

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.status, 'success')
    assert.ok(Array.isArray(res.body.data))
    assert.ok(res.body.data.length > 0)
    for (const item of res.body.data) {
      assert.equal(typeof item.id, 'number')
      assert.equal(typeof item.ChallengeId, 'number')
      assert.equal(typeof item.text, 'string')
      assert.ok(item.text.length > 0)
      assert.equal(typeof item.order, 'number')
      assert.equal(typeof item.unlocked, 'boolean')
    }
  })

  void it('GET all hints translates the hint texts into the requested language', async () => {
    assert.ok(germanHint)
    assert.notEqual(germanHint, englishHint)

    const res = await request(app)
      .get('/api/Hints')
      .set('Cookie', 'language=de_DE')

    assert.equal(res.status, 200)
    const texts = res.body.data.map((hint: { text: string }) => hint.text)
    assert.ok(texts.includes(germanHint))
    assert.ok(!texts.includes(englishHint))
  })

  void it('POST new hint is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .post('/api/Hints')
      .set(authHeader)
      .send({ ChallengeId: 1, text: 'Just look at the code!', order: 1, unlocked: false })

    assert.equal(res.status, 401)
  })
})

void describe('/api/Hints/:id', () => {
  void it('GET existing hint by id is forbidden via public API', async () => {
    const res = await request(app)
      .get(`/api/Hints/${await firstHintId()}`)

    assert.equal(res.status, 401)
  })

  void it('GET existing hint by id is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get(`/api/Hints/${await firstHintId()}`)
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('PUT unlock existing hint is allowed for anonymous users', async () => {
    const id = await firstHintId()
    const res = await request(app)
      .put(`/api/Hints/${id}`)
      .set(jsonHeader)
      .send({ unlocked: true })

    assert.equal(res.status, 200)
    assert.equal(res.body.status, 'success')
    assert.equal(res.body.data.id, id)
    assert.equal(res.body.data.unlocked, true)
  })

  void it('PUT unlock existing hint is allowed when authenticated', async () => {
    const id = await firstHintId()
    const res = await request(app)
      .put(`/api/Hints/${id}`)
      .set(authHeader)
      .send({ unlocked: true })

    assert.equal(res.status, 200)
    assert.equal(res.body.data.unlocked, true)
  })

  void it('DELETE existing hint is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .delete(`/api/Hints/${await firstHintId()}`)
      .set(authHeader)

    assert.equal(res.status, 401)
  })
})
