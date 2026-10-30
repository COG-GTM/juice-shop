/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { seededCredentials, seededSecurityAnswer } from '../../data/seedCredentials'
const expect = chai.expect

describe('seedCredentials', () => {
  const known = { password: 'admin123', totpSecret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH', securityAnswer: 'Samuel' }

  it('keeps the published credentials when seedKnownCredentials is enabled', () => {
    expect(seededCredentials('admin', known, true)).to.deep.equal(known)
  })

  it('randomizes password, TOTP secret and security answer when seedKnownCredentials is disabled', () => {
    const credentials = seededCredentials('jim', known, false)
    expect(credentials.password).to.not.equal(known.password)
    expect(credentials.password.length).to.be.at.least(32)
    expect(credentials.totpSecret).to.be.a('string').and.not.equal(known.totpSecret)
    expect(credentials.securityAnswer).to.be.a('string').and.not.equal(known.securityAnswer)
  })

  it('generates different passwords on every call', () => {
    expect(seededCredentials('jim', known, false).password).to.not.equal(seededCredentials('jim', known, false).password)
  })

  it('does not add a TOTP secret or security answer to users without one', () => {
    const credentials = seededCredentials('demo', { password: 'demo' }, false)
    expect(credentials.totpSecret).to.equal(undefined)
    expect(credentials.securityAnswer).to.equal(undefined)
  })

  it('uses the configured admin password for the admin account only', () => {
    expect(seededCredentials('admin', known, false, 'operator-chosen').password).to.equal('operator-chosen')
    expect(seededCredentials('jim', known, false, 'operator-chosen').password).to.not.equal('operator-chosen')
  })

  it('ignores an empty admin password override', () => {
    expect(seededCredentials('admin', known, false, '').password).to.not.be.oneOf(['', known.password])
  })

  it('randomizes standalone security answers when seedKnownCredentials is disabled', () => {
    expect(seededSecurityAnswer('ITsec', true)).to.equal('ITsec')
    expect(seededSecurityAnswer('ITsec', false)).to.not.equal('ITsec')
  })
})
