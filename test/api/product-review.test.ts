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
  let ownReviewId: string
  let ownerToken: string
  let otherToken: string
  const ownerEmail = 'mc.safesearch@juice-sh.op'
  const ownMessage = 'Review owned by MC SafeSearch'

  before(async () => {
    ownerToken = (await login(app, { email: ownerEmail, password: 'Mr. N00dles' })).token
    otherToken = (await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })).token
    await request(app)
      .put('/rest/products/1/reviews')
      .send({ message: ownMessage, author: ownerEmail })
    const res = await request(app)
      .get('/rest/products/1/reviews')
    reviewId = res.body.data[0]._id
    ownReviewId = res.body.data.find((review: { author: string, message: string }) => review.author === ownerEmail && review.message === ownMessage)._id
  })

  async function messageOf (id: string) {
    const res = await request(app)
      .get('/rest/products/1/reviews')
    return res.body.data.find((review: { _id: string }) => review._id === id)?.message
  }

  void it('PATCH own product review can be edited', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set({ Authorization: `Bearer ${ownerToken}`, 'content-type': 'application/json' })
      .send({
        id: ownReviewId,
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.modified, 1)
    assert.ok(Array.isArray(res.body.original))
    assert.ok(Array.isArray(res.body.updated))
    assert.equal(await messageOf(ownReviewId), 'Lorem Ipsum')
  })

  void it('PATCH product review of another user is forbidden', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set({ Authorization: `Bearer ${otherToken}`, 'content-type': 'application/json' })
      .send({
        id: ownReviewId,
        message: 'Forged'
      })
    assert.equal(res.status, 403)
    assert.equal(await messageOf(ownReviewId), 'Lorem Ipsum')
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

  void it('PATCH single product review editing needs a logged-in user', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set(authHeader)
      .send({
        id: reviewId,
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 401)
  })

  void it('POST non-existing product review cannot be liked', async () => {
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${otherToken}` })
      .send({
        id: 'does not exist'
      })
    assert.equal(res.status, 404)
  })

  void it('POST single product review can be liked', async () => {
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${otherToken}` })
      .send({
        id: reviewId
      })
    assert.equal(res.status, 200)
  })

  void it('PATCH multiple product reviews via injection is rejected', async () => {
    const message = 'trololololololololololololololololololololololololololol'
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set({ Authorization: `Bearer ${ownerToken}`, 'content-type': 'application/json' })
      .send({
        id: { $ne: -1 },
        message
      })
    assert.equal(res.status, 403)
    const reviews = await request(app)
      .get('/rest/products/1/reviews')
    assert.ok(reviews.body.data.every((review: { message: string }) => review.message !== message))
  })
})
