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
let bjoernToken: string
let adminToken: string

before(async () => {
  const result = await createTestApp()
  app = result.app
  bjoernToken = (await login(app, {
    email: 'bjoern.kimminich@gmail.com',
    password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
  })).token
  adminToken = (await login(app, {
    email: `admin@${config.get<string>('application.domain')}`,
    password: 'admin123'
  })).token
}, { timeout: 60000 })

void describe('/rest/products/:id/reviews', () => {
  void it('GET product reviews by product id', async () => {
    const res = await request(app)
      .get('/rest/products/1/reviews')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const review = res.body.data[0]
    assert.equal(typeof review.product, 'number')
    assert.equal(typeof review.message, 'string')
    assert.equal(typeof review.author, 'string')
  })

  void it('GET product reviews attack by injecting a mongoDB sleep command', async () => {
    const res = await request(app)
      .get('/rest/products/sleep(1)/reviews')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
  })

  // FIXME Turn on when #1960 is resolved
  void it.skip('GET product reviews by alphanumeric non-mongoDB-command product id', async () => {
    const res = await request(app)
      .get('/rest/products/kaboom/reviews')
    assert.equal(res.status, 400)
  })

  void it('PUT single product review can be created by an authenticated user', async () => {
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .set({ Authorization: `Bearer ${bjoernToken}` })
      .send({
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
  })

  void it('PUT product review creation needs an authenticated user', async () => {
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .send({
        message: 'Lorem Ipsum',
        author: 'Anonymous'
      })
    assert.equal(res.status, 401)
  })

  void it('PUT product review author is taken from the session, not the request body', async () => {
    const message = 'Forged review attempt ' + Date.now()
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .set({ Authorization: `Bearer ${bjoernToken}` })
      .send({
        message,
        author: `admin@${config.get<string>('application.domain')}`
      })
    assert.equal(res.status, 201)

    const reviews = await request(app).get('/rest/products/1/reviews')
    const created = reviews.body.data.find((review: { message: string }) => review.message === message)
    assert.equal(created.author, 'bjoern.kimminich@gmail.com')
  })

  void it('PUT product review with non-string or oversized message is rejected', async () => {
    for (const message of [{ $ne: -1 }, '', 'x'.repeat(161)]) {
      const res = await request(app)
        .put('/rest/products/1/reviews')
        .set({ Authorization: `Bearer ${bjoernToken}` })
        .send({ message })
      assert.equal(res.status, 400)
    }
  })
})

void describe('/rest/products/reviews', () => {
  let adminReviewId: string
  let otherReviewId: string

  before(async () => {
    const res = await request(app)
      .get('/rest/products/1/reviews')
    const reviews: Array<{ _id: string, author: string }> = res.body.data
    const adminEmail = `admin@${config.get<string>('application.domain')}`
    adminReviewId = reviews.find(review => review.author === adminEmail)!._id
    otherReviewId = reviews.find(review => review.author !== adminEmail)!._id
  })

  void it('PATCH own product review can be edited', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set({ Authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' })
      .send({
        id: adminReviewId,
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.modified, 1)
    assert.ok(Array.isArray(res.body.original))
    assert.ok(Array.isArray(res.body.updated))
  })

  void it('PATCH product review of another user is not modified', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set({ Authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' })
      .send({
        id: otherReviewId,
        message: 'Forged'
      })
    assert.equal(res.status, 200)
    assert.equal(res.body.modified, 0)

    const reviews = await request(app).get('/rest/products/1/reviews')
    const other = reviews.body.data.find((review: { _id: string }) => review._id === otherReviewId)
    assert.notEqual(other.message, 'Forged')
  })

  void it('PATCH single product review editing need an authenticated user', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .send({
        id: adminReviewId,
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 401)
  })

  void it('POST non-existing product review cannot be liked', async () => {
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${bjoernToken}` })
      .send({
        id: 'does not exist'
      })
    assert.equal(res.status, 404)
  })

  void it('POST single product review can be liked', async () => {
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${bjoernToken}` })
      .send({
        id: otherReviewId
      })
    assert.equal(res.status, 200)
  })

  void it('PATCH multiple product review via injection is rejected', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set({ Authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' })
      .send({
        id: { $ne: -1 },
        message: 'trololololololololololololololololololololololololololol'
      })
    assert.equal(res.status, 400)

    const reviews = await request(app).get('/rest/products/1/reviews')
    assert.ok(reviews.body.data.every((review: { message: string }) => review.message !== 'trololololololololololololololololololololololololololol'))
  })
})
