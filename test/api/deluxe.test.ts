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
import { WalletModel } from '../../models/wallet'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/deluxe-membership', () => {
  void it('GET deluxe membership status for customers', async () => {
    const { token } = await login(app, {
      email: 'bender@' + config.get<string>('application.domain'),
      password: 'OhG0dPlease1nsertLiquor!'
    })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const res = await request(app)
      .get('/rest/deluxe-membership')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.equal(res.body.data.membershipCost, 49)
  })

  void it('GET deluxe membership status for deluxe members throws error', async () => {
    const { token } = await login(app, {
      email: 'ciso@' + config.get<string>('application.domain'),
      password: 'mDLx?94T~1CfVfZMzw@sJ9f?s3L6lbMqE70FfI8^54jbNikY5fymx7c!YbJb'
    })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const res = await request(app)
      .get('/rest/deluxe-membership')
      .set(authHeader)

    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'You are already a deluxe member!')
  })

  void it('GET deluxe membership status for admin throws error', async () => {
    const { token } = await login(app, {
      email: 'admin@' + config.get<string>('application.domain'),
      password: 'admin123'
    })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const res = await request(app)
      .get('/rest/deluxe-membership')
      .set(authHeader)

    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'You are not eligible for deluxe membership!')
  })

  void it('GET deluxe membership status for accountant throws error', async () => {
    const { token } = await login(app, {
      email: 'accountant@' + config.get<string>('application.domain'),
      password: 'i am an awesome accountant'
    })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const res = await request(app)
      .get('/rest/deluxe-membership')
      .set(authHeader)

    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'You are not eligible for deluxe membership!')
  })

  void it('POST upgrade deluxe membership status for customers with card payment', async () => {
    const { token } = await login(app, {
      email: `bender@${config.get<string>('application.domain')}`,
      password: 'OhG0dPlease1nsertLiquor!'
    })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const cardsRes = await request(app)
      .get('/api/Cards')
      .set(authHeader)

    assert.equal(cardsRes.status, 200)

    const res = await request(app)
      .post('/rest/deluxe-membership')
      .set(authHeader)
      .send({
        paymentMode: 'card',
        paymentId: cardsRes.body.data[0].id.toString()
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.status, 'success')
  })

  void it('POST upgrade deluxe membership status for customers with wallet payment', async () => {
    const { token } = await login(app, {
      email: `mc.safesearch@${config.get<string>('application.domain')}`,
      password: 'Mr. N00dles'
    })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const res = await request(app)
      .post('/rest/deluxe-membership')
      .set(authHeader)
      .send({
        paymentMode: 'wallet'
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.status, 'success')
  })

  void it('POST upgrade deluxe membership fails for customers with insufficient wallet balance', async () => {
    const { token } = await login(app, {
      email: `amy@${config.get<string>('application.domain')}`,
      password: 'K1f.....................'
    })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const res = await request(app)
      .post('/rest/deluxe-membership')
      .set(authHeader)
      .send({
        paymentMode: 'wallet'
      })

    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'Insuffienct funds in Wallet')
  })

  void it('POST concurrent wallet upgrades debit the deluxe membership only once', async (t) => {
    const { token } = await login(app, {
      email: `morty@${config.get<string>('application.domain')}`,
      password: 'focusOnScienceMorty!focusOnScience'
    })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const balanceBefore = (await request(app).get('/rest/wallet/balance').set(authHeader)).body.data
    assert.ok(balanceBefore >= 49)

    const upgrades = 3
    const barrier = overlapWalletAccesses(t, upgrades)
    const responses = await Promise.all(Array.from({ length: upgrades }, async () => await request(app)
      .post('/rest/deluxe-membership')
      .set(authHeader)
      .send({ paymentMode: 'wallet' })))
    assert.ok(barrier.release() >= upgrades)

    const balanceAfter = (await request(app).get('/rest/wallet/balance').set(authHeader)).body.data
    assert.equal(balanceAfter, balanceBefore - 49)
    assert.equal(responses.filter(res => res.status === 200).length, 1)
  })

  void it('POST concurrent wallet upgrade and wallet checkout cannot spend the same balance twice', async (t) => {
    const { token } = await login(app, { email: `uvogin@${config.get<string>('application.domain')}`, password: 'muda-muda > ora-ora' })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const balanceBefore = (await request(app).get('/rest/wallet/balance').set(authHeader)).body.data
    const orderTotal = 5 * 8.99 + 2 * 4.99
    assert.ok(balanceBefore >= orderTotal && balanceBefore >= 49 && balanceBefore < orderTotal + 49)

    const barrier = overlapWalletAccesses(t, 2)
    const [upgrade, checkout] = await Promise.all([
      request(app).post('/rest/deluxe-membership').set(authHeader).send({ paymentMode: 'wallet' }),
      request(app).post('/rest/basket/5/checkout').set(authHeader).send({ orderDetails: { paymentId: 'wallet' } })
    ])
    assert.ok(barrier.release() >= 2)

    const balanceAfter = (await request(app).get('/rest/wallet/balance').set(authHeader)).body.data
    assert.ok(balanceAfter >= 0, `wallet balance went negative: ${balanceAfter}`)
    assert.equal([upgrade.status, checkout.status].filter(status => status === 200).length, 1)
    const expected = upgrade.status === 200 ? balanceBefore - 49 : balanceBefore - orderTotal + 5
    assert.ok(Math.abs(balanceAfter - expected) < 0.001)
  })

  void it('POST deluxe membership status with wrong card id throws error', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const res = await request(app)
      .post('/rest/deluxe-membership')
      .set(authHeader)
      .send({
        paymentMode: 'card',
        paymentId: 1337
      })

    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'Invalid Card')
  })

  void it('POST deluxe membership status for deluxe members throws error', async () => {
    const { token } = await login(app, {
      email: 'ciso@' + config.get<string>('application.domain'),
      password: 'mDLx?94T~1CfVfZMzw@sJ9f?s3L6lbMqE70FfI8^54jbNikY5fymx7c!YbJb'
    })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const res = await request(app)
      .post('/rest/deluxe-membership')
      .set(authHeader)
      .send({
        paymentMode: 'wallet'
      })

    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'Something went wrong. Please try again!')
  })

  void it('POST deluxe membership status for admin throws error', async () => {
    const { token } = await login(app, {
      email: 'admin@' + config.get<string>('application.domain'),
      password: 'admin123'
    })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const res = await request(app)
      .post('/rest/deluxe-membership')
      .set(authHeader)
      .send({
        paymentMode: 'wallet'
      })

    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'Something went wrong. Please try again!')
  })

  void it('POST deluxe membership status for accountant throws error', async () => {
    const { token } = await login(app, {
      email: 'accountant@' + config.get<string>('application.domain'),
      password: 'i am an awesome accountant'
    })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const res = await request(app)
      .post('/rest/deluxe-membership')
      .set(authHeader)
      .send({
        paymentMode: 'wallet'
      })

    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'Something went wrong. Please try again!')
  })
})

function overlapWalletAccesses (t: { mock: { method: (...args: any[]) => { mock: { restore: () => void } } } }, requests: number) {
  let walletAccesses = 0
  let releaseBarrier: () => void = () => {}
  const barrier = new Promise<void>(resolve => { releaseBarrier = resolve })
  const timeout = setTimeout(releaseBarrier, 5000)
  const awaitAllRequests = async () => {
    if (++walletAccesses === requests) releaseBarrier()
    await barrier
  }
  const mocks = (['findOne', 'update', 'decrement'] as const).map(method => {
    const original = (WalletModel[method] as (...args: unknown[]) => Promise<unknown>).bind(WalletModel)
    return t.mock.method(WalletModel, method, async (...args: unknown[]) => {
      await awaitAllRequests()
      return await original(...args)
    })
  })
  return {
    release () {
      clearTimeout(timeout)
      mocks.forEach(mock => { mock.mock.restore() })
      return walletAccesses
    }
  }
}
