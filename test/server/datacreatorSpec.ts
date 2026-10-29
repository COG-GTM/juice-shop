/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { resolveSeedPassword, usesShippedSecrets } from '../../data/datacreator'
const expect = chai.expect

describe('datacreator', () => {
  describe('resolveSeedPassword', () => {
    const envBackup = { ...process.env }

    beforeEach(() => {
      delete process.env.JUICE_SHOP_INSECURE_DEFAULT_CREDENTIALS
      delete process.env.JUICE_SHOP_SEED_PASSWORD_ADMIN
    })

    afterEach(() => {
      process.env = { ...envBackup }
    })

    it('should not use the shipped password for admin accounts by default', () => {
      const password = resolveSeedPassword('admin', 'admin', 'admin123', 'admin@juice-sh.op')
      expect(password).to.not.equal('admin123')
      expect(password.length).to.be.at.least(32)
    })

    it('should not use the shipped password for accounting accounts by default', () => {
      const password = resolveSeedPassword('accountant', 'accounting', 'i am an awesome accountant', 'accountant@juice-sh.op')
      expect(password).to.not.equal('i am an awesome accountant')
    })

    it('should generate a different password on every call', () => {
      expect(resolveSeedPassword('admin', 'admin', 'admin123', 'admin@juice-sh.op'))
        .to.not.equal(resolveSeedPassword('admin', 'admin', 'admin123', 'admin@juice-sh.op'))
    })

    it('should use the per-account environment variable override for privileged accounts', () => {
      process.env.JUICE_SHOP_SEED_PASSWORD_ADMIN = 'operator-chosen-secret'
      expect(resolveSeedPassword('admin', 'admin', 'admin123', 'admin@juice-sh.op')).to.equal('operator-chosen-secret')
    })

    it('should only use the shipped password for privileged accounts when explicitly opted in', () => {
      process.env.JUICE_SHOP_INSECURE_DEFAULT_CREDENTIALS = 'true'
      expect(resolveSeedPassword('admin', 'admin', 'admin123', 'admin@juice-sh.op')).to.equal('admin123')
    })

    it('should keep the shipped password for non-privileged accounts', () => {
      expect(resolveSeedPassword('jim', 'customer', 'ncc-1701', 'jim@juice-sh.op')).to.equal('ncc-1701')
    })
  })

  describe('usesShippedSecrets', () => {
    const envBackup = { ...process.env }

    beforeEach(() => {
      delete process.env.JUICE_SHOP_INSECURE_DEFAULT_CREDENTIALS
    })

    afterEach(() => {
      process.env = { ...envBackup }
    })

    it('should not use shipped secrets such as security answers for privileged accounts by default', () => {
      expect(usesShippedSecrets('admin')).to.equal(false)
      expect(usesShippedSecrets('accounting')).to.equal(false)
    })

    it('should use shipped secrets for privileged accounts when explicitly opted in', () => {
      process.env.JUICE_SHOP_INSECURE_DEFAULT_CREDENTIALS = 'true'
      expect(usesShippedSecrets('admin')).to.equal(true)
      expect(usesShippedSecrets('accounting')).to.equal(true)
    })

    it('should use shipped secrets for non-privileged accounts', () => {
      expect(usesShippedSecrets('customer')).to.equal(true)
      expect(usesShippedSecrets('deluxe')).to.equal(true)
    })
  })
})
