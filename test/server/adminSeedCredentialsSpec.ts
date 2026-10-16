/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import config from 'config'
import { staticAdminCredentialsEnabled, withGeneratedCredentials } from '../../lib/adminSeedCredentials'
import { loadStaticUserData, type StaticUser } from '../../data/staticData'

const expect = chai.expect

describe('adminSeedCredentials', () => {
  describe('withGeneratedCredentials', () => {
    let admins: StaticUser[]

    before(async () => {
      admins = (await loadStaticUserData()).filter(({ role }) => role === 'admin')
    })

    it('should replace the published password and security answer of every admin', () => {
      expect(admins).to.not.be.empty
      for (const admin of admins) {
        const seeded = withGeneratedCredentials(admin)
        expect(seeded.password).to.not.equal(admin.password)
        expect(seeded.password).to.have.length.of.at.least(32)
        if (admin.securityQuestion != null) {
          expect(seeded.securityQuestion?.id).to.equal(admin.securityQuestion.id)
          expect(seeded.securityQuestion?.answer).to.not.equal(admin.securityQuestion.answer)
        }
      }
    })

    it('should replace a published TOTP secret with a fresh base32 secret', () => {
      const wurstbrot = admins.find(({ username }) => username === 'wurstbrot')
      expect(wurstbrot?.totpSecret).to.be.a('string').that.is.not.empty
      const seeded = withGeneratedCredentials(wurstbrot!)
      expect(seeded.totpSecret).to.match(/^[A-Z2-7]{16,}$/)
      expect(seeded.totpSecret).to.not.equal(wurstbrot!.totpSecret)
    })

    it('should not add a TOTP secret to accounts without 2FA', () => {
      const admin = admins.find(({ key }) => key === 'admin')
      expect(withGeneratedCredentials(admin!).totpSecret).to.equal(admin!.totpSecret)
    })

    it('should generate different credentials on every call', () => {
      const admin = admins.find(({ key }) => key === 'admin')!
      expect(withGeneratedCredentials(admin).password).to.not.equal(withGeneratedCredentials(admin).password)
    })

    it('should keep all other account data', () => {
      const admin = admins.find(({ key }) => key === 'admin')!
      const { password, securityQuestion, totpSecret, ...rest } = withGeneratedCredentials(admin)
      const { password: _p, securityQuestion: _s, totpSecret: _t, ...original } = admin
      expect(rest).to.deep.equal(original)
    })
  })

  describe('staticAdminCredentialsEnabled', () => {
    const original = process.env.JUICE_SHOP_STATIC_ADMIN_CREDENTIALS

    afterEach(() => {
      if (original === undefined) {
        delete process.env.JUICE_SHOP_STATIC_ADMIN_CREDENTIALS
      } else {
        process.env.JUICE_SHOP_STATIC_ADMIN_CREDENTIALS = original
      }
    })

    it('should follow the application.staticAdminCredentials config without override', () => {
      delete process.env.JUICE_SHOP_STATIC_ADMIN_CREDENTIALS
      expect(staticAdminCredentialsEnabled()).to.equal(config.get<boolean>('application.staticAdminCredentials'))
    })

    it('should be enabled by JUICE_SHOP_STATIC_ADMIN_CREDENTIALS=true', () => {
      process.env.JUICE_SHOP_STATIC_ADMIN_CREDENTIALS = 'true'
      expect(staticAdminCredentialsEnabled()).to.equal(true)
    })

    it('should be disabled by any other JUICE_SHOP_STATIC_ADMIN_CREDENTIALS value', () => {
      process.env.JUICE_SHOP_STATIC_ADMIN_CREDENTIALS = 'false'
      expect(staticAdminCredentialsEnabled()).to.equal(false)
      process.env.JUICE_SHOP_STATIC_ADMIN_CREDENTIALS = 'yes'
      expect(staticAdminCredentialsEnabled()).to.equal(false)
    })
  })
})
