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
import { UserModel } from '../../models/user'
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

  void it('POST upgrade deluxe membership without paymentMode is rejected', async () => {
    const { token } = await login(app, {
      email: `uvogin@${config.get<string>('application.domain')}`,
      password: 'muda-muda > ora-ora'
    })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const res = await request(app)
      .post('/rest/deluxe-membership')
      .set(authHeader)
      .send({})

    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'Invalid payment mode')
    const user = await UserModel.findOne({ where: { email: `uvogin@${config.get<string>('application.domain')}` } })
    assert.equal(user?.role, 'customer')
  })

  void it('POST upgrade deluxe membership with unknown paymentMode is rejected', async () => {
    const { token } = await login(app, {
      email: `basil@${config.get<string>('application.domain')}`,
      password: 'my little nest of vipers'
    })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const res = await request(app)
      .post('/rest/deluxe-membership')
      .set(authHeader)
      .send({ paymentMode: 'free' })

    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'Invalid payment mode')
    const user = await UserModel.findOne({ where: { email: `basil@${config.get<string>('application.domain')}` } })
    assert.equal(user?.role, 'customer')
  })

  void it('POST upgrade deluxe membership with wallet payment fails for customers without a wallet', async () => {
    const email = `morty@${config.get<string>('application.domain')}`
    const { token } = await login(app, { email, password: 'focusOnScienceMorty!focusOnScience' })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const user = await UserModel.findOne({ where: { email } })
    await WalletModel.destroy({ where: { UserId: user?.id } })

    const res = await request(app)
      .post('/rest/deluxe-membership')
      .set(authHeader)
      .send({ paymentMode: 'wallet' })

    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'Insuffienct funds in Wallet')
    await user?.reload()
    assert.equal(user?.role, 'customer')
  })

  void it('POST upgrade deluxe membership with concurrent wallet payments never overdraws the wallet', async () => {
    const email = `john@${config.get<string>('application.domain')}`
    const { token } = await login(app, { email, password: 'y&x5Z#f6W532Z4445#Ae2HkwZVyDb7&oCUaDzFU' })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const user = await UserModel.findOne({ where: { email } })
    await WalletModel.update({ balance: 49 }, { where: { UserId: user?.id } })

    const responses = await Promise.all([1, 2, 3].map(async () => await request(app)
      .post('/rest/deluxe-membership')
      .set(authHeader)
      .send({ paymentMode: 'wallet' })))

    assert.equal(responses.filter(res => res.status === 200).length, 1)
    const wallet = await WalletModel.findOne({ where: { UserId: user?.id } })
    assert.equal(wallet?.balance, 0)
  })
  void it('POST upgrade deluxe membership with concurrent wallet payments only charges once', async () => {
    const email = `emma@${config.get<string>('application.domain')}`
    const { token } = await login(app, { email, password: 'y&x5Z#f6W532ZUf$q3DsdgfgfgxxUsvoCUaDzFU' })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const user = await UserModel.findOne({ where: { email } })
    await WalletModel.update({ balance: 98 }, { where: { UserId: user?.id } })

    const responses = await Promise.all([1, 2, 3].map(async () => await request(app)
      .post('/rest/deluxe-membership')
      .set(authHeader)
      .send({ paymentMode: 'wallet' })))

    assert.equal(responses.filter(res => res.status === 200).length, 1)
    const wallet = await WalletModel.findOne({ where: { UserId: user?.id } })
    assert.equal(wallet?.balance, 49)
  })
})
