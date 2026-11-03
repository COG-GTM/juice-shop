/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { safeLoad } from 'js-yaml'
import { loadStaticUserData, type StaticUser } from '../../data/staticData'
import { privilegedRoles, resolveSeedCredentials, seedEnvSuffix } from '../../lib/seedCredentials'

const expect = chai.expect

function makeUser (role: StaticUser['role'], key = 'some-key', totpSecret?: string): Pick<StaticUser, 'key' | 'role' | 'password' | 'totpSecret'> {
  return {
    key,
    role,
    password: 'yml-password',
    ...(totpSecret == null ? {} : { totpSecret })
  }
}

describe('seedCredentials', () => {
  it('keeps customer credentials from the static data with either config setting', () => {
    const user = makeUser('customer', 'customer', 'CUSTOMER_TOTP_SECRET')

    for (const useDefaultCredentials of [false, true]) {
      expect(resolveSeedCredentials(user, useDefaultCredentials, {})).to.deep.equal({
        password: user.password,
        totpSecret: user.totpSecret,
        randomized: false
      })
    }
  })

  for (const role of ['admin', 'accounting', 'deluxe'] as const) {
    it(`randomizes ${role} credentials when default credentials are disabled`, () => {
      const user = makeUser(role, role)
      const first = resolveSeedCredentials(user, false, {})
      const second = resolveSeedCredentials(user, false, {})

      expect(first.password).to.not.equal(user.password)
      expect(first.password.length).to.be.at.least(32)
      expect(second.password).to.not.equal(first.password)
      expect(first.randomized).to.equal(true)
      expect(second.randomized).to.equal(true)
    })
  }

  it('returns static credentials when default credentials are enabled', () => {
    const user = makeUser('admin', 'timo', 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH')

    expect(resolveSeedCredentials(user, true, {})).to.deep.equal({
      password: user.password,
      totpSecret: user.totpSecret,
      randomized: false
    })
  })

  it('uses environment credential overrides when default credentials are disabled', () => {
    const admin = makeUser('admin', 'admin')
    const timo = makeUser('admin', 'timo', 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH')

    expect(resolveSeedCredentials(admin, false, { JUICE_SHOP_SEED_PASSWORD_ADMIN: 'x' }).password).to.equal('x')
    expect(resolveSeedCredentials(timo, false, { JUICE_SHOP_SEED_TOTP_SECRET_TIMO: 'TOTP_OVERRIDE' }).totpSecret).to.equal('TOTP_OVERRIDE')
  })

  it('randomizes a static TOTP secret when default credentials are disabled', () => {
    const user = makeUser('admin', 'timo', 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH')
    const result = resolveSeedCredentials(user, false, {})

    expect(result.totpSecret).to.match(/^[A-Z2-7]+=*$/)
    expect(result.totpSecret).to.not.equal(user.totpSecret)
    expect(result.randomized).to.equal(true)
  })

  it('leaves the TOTP secret undefined when static data has none', () => {
    const user = makeUser('admin', 'admin')

    expect(resolveSeedCredentials(user, false, {}).totpSecret).to.equal(undefined)
  })

  it('converts seed account keys to environment variable suffixes', () => {
    expect(seedEnvSuffix('bjoernGoogle')).to.equal('BJOERN_GOOGLE')
    expect(seedEnvSuffix('LetUsTest')).to.equal('LET_US_TEST')
  })

  it('disables default seed credentials in the default config', async () => {
    const contents = await readFile(path.resolve('config/default.yml'), 'utf8')
    const defaultConfig = safeLoad(contents) as { application?: { seedDefaultCredentials?: boolean } }

    expect(defaultConfig.application?.seedDefaultCredentials).to.equal(false)
  })

  it('randomizes the password of every privileged static user when defaults are disabled', async () => {
    const users = await loadStaticUserData()
    const privilegedUsers = users.filter(({ role }) => privilegedRoles.includes(role))

    expect(privilegedUsers.length).to.be.greaterThan(0)
    for (const user of privilegedUsers) {
      const result = resolveSeedCredentials(user, false, {})
      expect(result.password, `Expected ${user.key} to have a randomized password`).to.not.equal(user.password)
    }
  })
})
