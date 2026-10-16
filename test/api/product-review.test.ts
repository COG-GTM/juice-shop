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
import { type Product } from '../../data/types'
import * as security from '../../lib/insecurity'

let app: Express

const authHeader = { Authorization: `Bearer ${security.authorize()}`, 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
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

  void it('PUT single product review can be created and is attributed to the authenticated user', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const message = 'Lorem Ipsum ' + Date.now()
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        message,
        author: 'admin@' + config.get<string>('application.domain')
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))

    const reviewsRes = await request(app)
      .get('/rest/products/1/reviews')
    const review = reviewsRes.body.data.find((r: { message: string }) => r.message === message)
    assert.ok(review)
    assert.equal(review.author, 'bjoern.kimminich@gmail.com')
  })

  void it('PUT single product review is attributed from the verified token when it is not in the token cache', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    delete security.authenticatedUsers.tokenMap[token]
    const message = 'Lorem Ipsum uncached ' + Date.now()
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        message,
        author: 'admin@' + config.get<string>('application.domain')
      })
    assert.equal(res.status, 201)

    const reviewsRes = await request(app)
      .get('/rest/products/1/reviews')
    const review = reviewsRes.body.data.find((r: { message: string }) => r.message === message)
    assert.ok(review)
    assert.equal(review.author, 'bjoern.kimminich@gmail.com')
  })

  void it('PUT single product review creation needs an authenticated user', async () => {
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .send({
        message: 'Lorem Ipsum',
        author: 'admin@' + config.get<string>('application.domain')
      })
    assert.equal(res.status, 401)
  })

  void it('PUT single product review rejects missing, blank, non-string and overlong messages', async () => {
    const reviewerAuth = { Authorization: `Bearer ${security.authorize({ data: { email: 'review.validation@' + config.get<string>('application.domain') } })}` }
    for (const body of [{}, { message: '   ' }, { message: { $gt: '' } }, { message: 'x'.repeat(161) }]) {
      const res = await request(app)
        .put('/rest/products/1/reviews')
        .set(reviewerAuth)
        .send(body)
      assert.equal(res.status, 400)
    }
  })

  void it('PUT single product review creation is rate limited per user', async () => {
    const reviewerAuth = { Authorization: `Bearer ${security.authorize({ data: { email: 'review.ratelimit@' + config.get<string>('application.domain') } })}` }
    for (let i = 0; i < 10; i++) {
      const res = await request(app)
        .put('/rest/products/1/reviews')
        .set(reviewerAuth)
        .send({ message: '' })
      assert.equal(res.status, 400)
    }
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .set(reviewerAuth)
      .send({ message: 'Lorem Ipsum' })
    assert.equal(res.status, 429)
  })
})

void describe('/rest/products/reviews', () => {
  let reviewId: string

  before(async () => {
    const res = await request(app)
      .get('/rest/products/1/reviews')
    const response = res.body
    reviewId = response.data[0]._id
  })

  void it('PATCH single product review can be edited', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set(authHeader)
      .send({
        id: reviewId,
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.modified, 'number')
    assert.ok(Array.isArray(res.body.original))
    assert.ok(Array.isArray(res.body.updated))
  })

  void it('PATCH single product review editing need an authenticated user', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .send({
        id: reviewId,
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 401)
  })

  void it('POST non-existing product review cannot be liked', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        id: 'does not exist'
      })
    assert.equal(res.status, 404)
  })

  void it('POST single product review can be liked', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        id: reviewId
      })
    assert.equal(res.status, 200)
  })

  void it('PATCH multiple product review via injection', async () => {
    const totalReviews = config.get<Product[]>('products').reduce((sum: number, { reviews = [] }: any) => sum + reviews.length, 2)

    const res = await request(app)
      .patch('/rest/products/reviews')
      .set(authHeader)
      .send({
        id: { $ne: -1 },
        message: 'trololololololololololololololololololololololololololol'
      })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.modified, 'number')
    assert.ok(Array.isArray(res.body.original))
    assert.ok(Array.isArray(res.body.updated))
    assert.equal(res.body.modified, totalReviews)
  })
})
