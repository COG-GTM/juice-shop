/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { Sequelize } from 'sequelize'
import { UserModel, UserModelInit } from '../../models/user'
const expect = chai.expect

describe('UserModel email', () => {
  before(() => {
    UserModelInit(new Sequelize({ dialect: 'sqlite', storage: ':memory:', logging: false }))
  })

  async function validationErrorFor (email: string) {
    try {
      await UserModel.build({ email, password: 'ncc-1701' }).validate()
      return null
    } catch (err: any) {
      return err
    }
  }

  it('accepts a well-formed email address', async () => {
    expect(await validationErrorFor('jim@juice-sh.op')).to.equal(null)
  })

  it('accepts empty or whitespace-only email as used by the empty user registration challenge', async () => {
    expect(await validationErrorFor('')).to.equal(null)
    expect(await validationErrorFor(' ')).to.equal(null)
  })

  it('accepts a well-formed email address with surrounding whitespace', async () => {
    expect(await validationErrorFor(' test@gmail.com ')).to.equal(null)
  })

  for (const email of [
    '<iframe src="javascript:alert(`xss`)">',
    '<iframe src="javascript:alert(1)">@juice-sh.op',
    '<img src=x onerror=alert(1)>@evil.test',
    'not-an-email',
    'mallory@'
  ]) {
    it(`rejects ${email} regardless of the persistedXssUser challenge`, async () => {
      const err = await validationErrorFor(email)
      expect(err).to.have.property('name', 'SequelizeValidationError')
      expect(err.errors[0]).to.have.property('path', 'email')
    })
  }
})
