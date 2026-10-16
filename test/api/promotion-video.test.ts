/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import fs from 'node:fs'
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

  void it('GET promotion video page contains subtitles as JSON data block', async () => {
    const res = await request(app)
      .get('/promotion')
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<script id="subtitle" type="application/json" data-label="English" data-lang="en">'))
  })

  void it('GET promotion video page sends a nonce-based Content-Security-Policy', async () => {
    const res = await request(app)
      .get('/promotion')
    const csp = res.headers['content-security-policy']
    assert.match(csp, /script-src 'self' 'nonce-[0-9a-f]{32}'/)
    const nonce = /'nonce-([0-9a-f]{32})'/.exec(csp)?.[1]
    assert.ok(res.text.includes(`<script nonce="${nonce}">`))
  })

  void it('GET promotion video page does not let subtitle content break out of its <script> block', async () => {
    const subtitlesFile = 'frontend/dist/frontend/assets/public/videos/owasp_promo.vtt'
    const original = fs.readFileSync(subtitlesFile, 'utf8')
    const payload = 'WEBVTT\n\n00:00:01.000 --> 00:00:02.000\n</script><script>alert(`xss`)</script> & <b>\u2028'
    fs.writeFileSync(subtitlesFile, payload)
    try {
      const res = await request(app)
        .get('/promotion')
      assert.equal(res.status, 200)
      assert.ok(!res.text.includes('</script><script>alert(`xss`)</script>'))
      const block = /<script id="subtitle" type="application\/json"[^>]*>([^<]*)<\/script>/.exec(res.text)
      assert.ok(block)
      assert.equal(JSON.parse(block[1]), payload)
    } finally {
      fs.writeFileSync(subtitlesFile, original)
    }
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
