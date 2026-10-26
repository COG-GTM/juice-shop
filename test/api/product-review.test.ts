/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
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

  void it('PUT single product review can be created', async () => {
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .send({
        message: 'Lorem Ipsum',
        author: 'Anonymous'
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
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

  void it('PATCH own product review can be edited', async () => {
    const email = 'bjoern.kimminich@gmail.com'
    const { token } = await login(app, {
      email,
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const userAuthHeader = { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
    await request(app)
      .put('/rest/products/2/reviews')
      .set(userAuthHeader)
      .send({ message: 'Own review', author: email })
    const reviews = await request(app).get('/rest/products/2/reviews')
    const ownReview = reviews.body.data.find((review: { author: string, message: string }) => review.author === email && review.message === 'Own review')

    const res = await request(app)
      .patch('/rest/products/reviews')
      .set(userAuthHeader)
      .send({
        id: ownReview._id,
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.modified, 1)
    assert.ok(Array.isArray(res.body.original))
    assert.ok(Array.isArray(res.body.updated))
    assert.equal(res.body.updated[0].message, 'Lorem Ipsum')
  })

  void it('PATCH own product review can be edited with a valid bearer token unknown to the server despite a different token cookie', async () => {
    const email = 'bjoern.kimminich@gmail.com'
    const { token } = await login(app, {
      email,
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const userAuthHeader = { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
    await request(app)
      .put('/rest/products/3/reviews')
      .set(userAuthHeader)
      .send({ message: 'Own review after restart', author: email })
    const reviews = await request(app).get('/rest/products/3/reviews')
    const ownReview = reviews.body.data.find((review: { author: string, message: string }) => review.author === email && review.message === 'Own review after restart')
    delete security.authenticatedUsers.tokenMap[token]
    const otherToken = security.authorize({ data: { id: 4711, email: 'other@juice-sh.op' } })

    const res = await request(app)
      .patch('/rest/products/reviews')
      .set(userAuthHeader)
      .set('Cookie', `token=${otherToken}`)
      .send({
        id: ownReview._id,
        message: 'Edited after restart'
      })
    assert.equal(res.status, 200)
    assert.equal(res.body.modified, 1)
  })

  void it('PATCH product review of another user cannot be edited', async () => {
    const { token } = await login(app, {
      email: 'mc.safesearch@juice-sh.op',
      password: 'Mr. N00dles'
    })
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({
        id: reviewId,
        message: 'Forged'
      })
    assert.equal(res.status, 200)
    assert.equal(res.body.modified, 0)
  })

  void it('PATCH product review editing needs a token of a known user', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set(authHeader)
      .send({
        id: reviewId,
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 401)
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

  void it('PATCH multiple product reviews via injection is rejected', async () => {
    const { token } = await login(app, {
      email: 'mc.safesearch@juice-sh.op',
      password: 'Mr. N00dles'
    })
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({
        id: { $ne: -1 },
        message: 'trololololololololololololololololololololololololololol'
      })
    assert.equal(res.status, 400)
  })
})
