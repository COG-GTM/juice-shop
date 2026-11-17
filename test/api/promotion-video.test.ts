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

  void it('GET promotion video page references subtitles instead of embedding them', async () => {
    const res = await request(app)
      .get('/promotion')
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<div id="subtitle" data-src="./promotion/subtitles" data-label="English" data-lang="en" hidden>'))
    assert.ok(!res.text.includes('WEBVTT'))
  })
})

void describe('/promotion/subtitles', () => {
  void it('GET promotion video subtitles are served as text/vtt', async () => {
    const res = await request(app)
      .get('/promotion/subtitles')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/vtt'))
    assert.equal(res.headers['x-content-type-options'], 'nosniff')
    assert.ok(res.text.startsWith('WEBVTT'))
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
