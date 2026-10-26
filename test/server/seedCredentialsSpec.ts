/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { resolveSeedCredentials } from '../../data/seedCredentials'
const expect = chai.expect

describe('seedCredentials', () => {
  const admin = { key: 'admin', password: 'admin123', securityQuestion: { id: 2, answer: '@xI98PxDO+06!' } }
  const accountant = { key: 'accountant', password: 'i am an awesome accountant' }
  const wurstbrot = { key: 'wurstbrot', password: 'EinBelegtesBrotMitSchinkenSCHINKEN!', totpSecret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH' }

  describe('by default', () => {
    const env = {}

    it('does not use the published admin password', () => {
      const credentials = resolveSeedCredentials(admin, env)
      expect(credentials.password).to.not.equal('admin123')
      expect(credentials.generatedAdminPassword).to.equal(credentials.password)
    })

    it('does not use the published password for other users', () => {
      const credentials = resolveSeedCredentials(accountant, env)
      expect(credentials.password).to.not.equal('i am an awesome accountant')
      expect(credentials.password).to.have.length.of.at.least(24)
      expect(credentials.generatedAdminPassword).to.equal(undefined)
    })

    it('generates different passwords on each call', () => {
      expect(resolveSeedCredentials(accountant, env).password).to.not.equal(resolveSeedCredentials(accountant, env).password)
    })

    it('replaces the published TOTP secret', () => {
      const credentials = resolveSeedCredentials(wurstbrot, env)
      expect(credentials.totpSecret).to.be.a('string').and.not.equal(wurstbrot.totpSecret)
    })

    it('does not add a TOTP secret to users without one', () => {
      expect(resolveSeedCredentials(accountant, env).totpSecret).to.equal(undefined)
    })

    it('replaces the published security answer but keeps the question', () => {
      const credentials = resolveSeedCredentials(admin, env)
      expect(credentials.securityQuestion?.id).to.equal(2)
      expect(credentials.securityQuestion?.answer).to.not.equal('@xI98PxDO+06!')
    })

    it('uses JUICE_SHOP_ADMIN_PASSWORD for the admin account when set', () => {
      const credentials = resolveSeedCredentials(admin, { JUICE_SHOP_ADMIN_PASSWORD: 'operator-chosen' })
      expect(credentials.password).to.equal('operator-chosen')
      expect(credentials.generatedAdminPassword).to.equal(undefined)
    })

    it('does not apply JUICE_SHOP_ADMIN_PASSWORD to other users', () => {
      expect(resolveSeedCredentials(accountant, { JUICE_SHOP_ADMIN_PASSWORD: 'operator-chosen' }).password).to.not.equal('operator-chosen')
    })
  })

  describe('with JUICE_SHOP_DEMO_CREDENTIALS=true', () => {
    const env = { JUICE_SHOP_DEMO_CREDENTIALS: 'true' }

    it('uses the published credentials', () => {
      expect(resolveSeedCredentials(admin, env)).to.deep.equal({ password: 'admin123', totpSecret: undefined, securityQuestion: admin.securityQuestion })
      expect(resolveSeedCredentials(wurstbrot, env).totpSecret).to.equal(wurstbrot.totpSecret)
    })
  })
})
