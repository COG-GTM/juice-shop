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

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let addressId: string

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const { token } = await login(app, {
      email: 'jim@juice-sh.op',
      password: 'ncc-1701'
    })
    authHeader = {
      Authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    }
  },
  { timeout: 60000 }
)

void describe('/api/Addresss', () => {
  void it('GET all addresses is forbidden via public API', async () => {
    const res = await request(app).get('/api/Addresss')
    assert.equal(res.status, 401)
  })

  void it('GET all addresses', async () => {
    const res = await request(app).get('/api/Addresss').set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('POST new address with all valid fields', async () => {
    const res = await request(app).post('/api/Addresss').set(authHeader).send({
      fullName: 'Jim',
      mobileNum: '9800000000',
      zipCode: 'NX 101',
      streetAddress: 'Bakers Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    assert.equal(res.status, 201)
  })

  void it('POST new address with invalid pin code', async () => {
    const res = await request(app).post('/api/Addresss').set(authHeader).send({
      fullName: 'Jim',
      mobileNum: '9800000000',
      zipCode: 'NX 10111111',
      streetAddress: 'Bakers Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    assert.equal(res.status, 400)
  })

  void it('POST new address with invalid mobile number', async () => {
    const res = await request(app).post('/api/Addresss').set(authHeader).send({
      fullName: 'Jim',
      mobileNum: '10000000000',
      zipCode: 'NX 101',
      streetAddress: 'Bakers Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    assert.equal(res.status, 400)
  })

  void it('POST new address is forbidden via public API', async () => {
    const res = await request(app).post('/api/Addresss').send({
      fullName: 'Jim',
      mobileNum: '9800000000',
      zipCode: 'NX 10111111',
      streetAddress: 'Bakers Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    assert.equal(res.status, 401)
  })
})

void describe('/api/Addresss/:id', () => {
  before(async () => {
    const res = await request(app).post('/api/Addresss').set(authHeader).send({
      fullName: 'Jim',
      mobileNum: '9800000000',
      zipCode: 'NX 101',
      streetAddress: 'Bakers Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    assert.equal(res.status, 201)
    addressId = res.body.data.id
  })

  void it('GET address by id is forbidden via public API', async () => {
    const res = await request(app).get('/api/Addresss/' + addressId)
    assert.equal(res.status, 401)
  })

  void it('PUT update address is forbidden via public API', async () => {
    const res = await request(app)
      .put('/api/Addresss/' + addressId)
      .set({ 'content-type': 'application/json' })
      .send({ quantity: 2 })
    assert.equal(res.status, 401)
  })

  void it('DELETE address by id is forbidden via public API', async () => {
    const res = await request(app).delete('/api/Addresss/' + addressId)
    assert.equal(res.status, 401)
  })

  void it('GET address by id', async () => {
    const res = await request(app)
      .get('/api/Addresss/' + addressId)
      .set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('GET address by non-existing id returns 400 for authorized user', async () => {
    const nonExistingId = 999999
    const res = await request(app)
      .get('/api/Addresss/' + nonExistingId)
      .set(authHeader)
    assert.equal(res.status, 400)
    assert.equal(res.body.status, 'error')
    assert.equal(res.body.data, 'Malicious activity detected.')
  })

  void it('PUT update address by id', async () => {
    const res = await request(app)
      .put('/api/Addresss/' + addressId)
      .set(authHeader)
      .send({ fullName: 'Jimy' })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.fullName, 'Jimy')
  })

  void it('PUT update address by id with invalid mobile number is forbidden', async () => {
    const res = await request(app)
      .put('/api/Addresss/' + addressId)
      .set(authHeader)
      .send({ mobileNum: '10000000000' })
    assert.equal(res.status, 400)
  })

  void it('PUT update address by id with invalid pin code is forbidden', async () => {
    const res = await request(app)
      .put('/api/Addresss/' + addressId)
      .set(authHeader)
      .send({ zipCode: 'NX 10111111' })
    assert.equal(res.status, 400)
  })

  void it('DELETE address by id', async () => {
    const res = await request(app)
      .delete('/api/Addresss/' + addressId)
      .set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('DELETE address by id again returns 400 for authorized user', async () => {
    const res = await request(app)
      .delete('/api/Addresss/' + addressId)
      .set(authHeader)
    assert.equal(res.status, 400)
    assert.equal(res.body.status, 'error')
    assert.equal(res.body.data, 'Malicious activity detected.')
  })
})

async function freshClient (): Promise<{ app: Express, headers: typeof authHeader }> {
  const { app } = await createTestApp()
  const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  return { app, headers: { Authorization: 'Bearer ' + token, 'content-type': 'application/json' } }
}

void describe('/api/Addresss rate limiting', () => {
  void it('allows 300 requests per 5 minutes from the same client and rejects the next one', async () => {
    const { app, headers } = await freshClient()
    for (let i = 0; i < 300; i++) {
      const res = await request(app).get('/api/Addresss').set(headers)
      assert.notEqual(res.status, 429, `request ${i + 1} was throttled`)
    }
    const res = await request(app).get('/api/Addresss').set(headers)
    assert.equal(res.status, 429)
  })

  void it('ignores X-Forwarded-For when identifying the client', async () => {
    const { app, headers } = await freshClient()
    const put = async (i: number) => await request(app)
      .put('/api/Addresss/1')
      .set(headers)
      .set('X-Forwarded-For', `203.0.${Math.floor(i / 256)}.${i % 256}`)
      .send({ city: 'Gotham' })
    for (let i = 0; i < 300; i++) {
      assert.notEqual((await put(i)).status, 429, `request ${i + 1} was throttled`)
    }
    assert.equal((await put(300)).status, 429)
  })
})
