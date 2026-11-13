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

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/promotion', () => {
  void it('GET promotion video page is publicly accessible', async () => {
    const res = await request(app)
      .get('/promotion')
    assert.equal(res.status, 200)
  })

  void it('GET promotion video page contains embedded video', async () => {
    const res = await request(app)
      .get('/promotion')
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<source src="./video" type="video/mp4">'))
  })

  void it('GET promotion video page contains subtitles as <script>', async () => {
    const res = await request(app)
      .get('/promotion')
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<script id="subtitle" type="text/vtt" data-label="English" data-lang="en">'))
  })
})

void describe('/video', () => {
  void it('GET promotion video is publicly accessible', async () => {
    const res = await request(app)
      .get('/video')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('video/mp4'))
  })
})

void describe('File serving rate limit', () => {
  void it('GET file-serving routes respond with 429 once the per-IP limit is exhausted', async () => {
    const easterEgg = '/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg'
    let res = await request(app).get(easterEgg)
    let requests = 1
    while (res.status !== 429 && requests <= 1000) {
      res = await request(app).get(easterEgg)
      requests++
    }
    assert.equal(res.status, 429)
    assert.ok(requests > 100)
    res = await request(app).get('/video')
    assert.equal(res.status, 429)
    res = await request(app).get('/promotion')
    assert.equal(res.status, 429)
  })
})
