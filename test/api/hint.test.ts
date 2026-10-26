/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express
const jsonHeader = { 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function firstHint () {
  const res = await request(app).get('/api/Hints')
  assert.equal(res.status, 200)
  return res.body.data[0]
}

void describe('/api/Hints/:id', () => {
  void it('PUT with hint text is forbidden and leaves the hint unchanged', async () => {
    const hint = await firstHint()

    const res = await request(app)
      .put(`/api/Hints/${hint.id}`)
      .set(jsonHeader)
      .send({ text: 'Tampered hint' })

    assert.equal(res.status, 403)
    assert.equal((await firstHint()).text, hint.text)
  })

  void it('PUT with hint text alongside unlocked is forbidden', async () => {
    const hint = await firstHint()

    const res = await request(app)
      .put(`/api/Hints/${hint.id}`)
      .set(jsonHeader)
      .send({ unlocked: true, text: 'Tampered hint' })

    assert.equal(res.status, 403)
    assert.equal((await firstHint()).text, hint.text)
  })

  void it('PUT re-locking a hint is forbidden', async () => {
    const hint = await firstHint()

    const res = await request(app)
      .put(`/api/Hints/${hint.id}`)
      .set(jsonHeader)
      .send({ unlocked: false })

    assert.equal(res.status, 403)
  })

  void it('PUT { unlocked: true } unlocks the hint anonymously', async () => {
    const hint = await firstHint()

    const res = await request(app)
      .put(`/api/Hints/${hint.id}`)
      .set(jsonHeader)
      .send({ unlocked: true })

    assert.equal(res.status, 200)
    assert.equal(res.body.data.unlocked, true)
    assert.equal(res.body.data.text, hint.text)
  })
})
