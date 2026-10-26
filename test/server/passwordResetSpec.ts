/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import * as passwordReset from '../../lib/passwordReset'
const expect = chai.expect

describe('passwordReset', () => {
  let sentTokens: Record<string, string>
  let clock: sinon.SinonFakeTimers

  beforeEach(() => {
    sentTokens = {}
    passwordReset.resetPasswordResetState()
    passwordReset.setPasswordResetMailer(async (email, token) => { sentTokens[email] = token })
    clock = sinon.useFakeTimers({ now: Date.now(), toFake: ['Date'] })
  })

  afterEach(() => {
    clock.restore()
    passwordReset.setPasswordResetMailer()
    passwordReset.resetPasswordResetState()
  })

  describe('reset tokens', () => {
    it('delivers a random 256-bit token to the account email address', async () => {
      await passwordReset.issueResetToken(1, 'jim@juice-sh.op')
      expect(sentTokens['jim@juice-sh.op']).to.match(/^[0-9a-f]{64}$/)
    })

    it('accepts a token only for the account it was issued for', async () => {
      await passwordReset.issueResetToken(1, 'jim@juice-sh.op')
      const token = sentTokens['jim@juice-sh.op']
      expect(passwordReset.isValidResetToken(token, 1)).to.equal(true)
      expect(passwordReset.isValidResetToken(token, 2)).to.equal(false)
    })

    it('rejects unknown tokens', () => {
      expect(passwordReset.isValidResetToken('a'.repeat(64), 1)).to.equal(false)
    })

    it('rejects expired tokens', async () => {
      await passwordReset.issueResetToken(1, 'jim@juice-sh.op')
      const token = sentTokens['jim@juice-sh.op']
      clock.tick(passwordReset.RESET_TOKEN_TTL_MS + 1)
      expect(passwordReset.isValidResetToken(token, 1)).to.equal(false)
    })

    it('invalidates previously issued tokens when a new one is requested', async () => {
      await passwordReset.issueResetToken(1, 'jim@juice-sh.op')
      const oldToken = sentTokens['jim@juice-sh.op']
      await passwordReset.issueResetToken(1, 'jim@juice-sh.op')
      expect(passwordReset.isValidResetToken(oldToken, 1)).to.equal(false)
      expect(passwordReset.isValidResetToken(sentTokens['jim@juice-sh.op'], 1)).to.equal(true)
    })

    it('removes expired tokens when new tokens are issued', async () => {
      await passwordReset.issueResetToken(1, 'jim@juice-sh.op')
      clock.tick(passwordReset.RESET_TOKEN_TTL_MS + 1)
      await passwordReset.issueResetToken(2, 'bender@juice-sh.op')
      expect(passwordReset.pendingResetTokenCount()).to.equal(1)
    })

    it('invalidates tokens after use', async () => {
      await passwordReset.issueResetToken(1, 'jim@juice-sh.op')
      const token = sentTokens['jim@juice-sh.op']
      passwordReset.invalidateResetTokens(1)
      expect(passwordReset.isValidResetToken(token, 1)).to.equal(false)
    })
  })

  describe('account lockout', () => {
    it('locks an account after too many failed attempts regardless of email casing', () => {
      for (let i = 0; i < passwordReset.MAX_FAILED_RESET_ATTEMPTS - 1; i++) {
        passwordReset.registerFailedAttempt('Jim@Juice-sh.op')
      }
      expect(passwordReset.isLockedOut('jim@juice-sh.op')).to.equal(false)
      passwordReset.registerFailedAttempt('jim@juice-sh.op ')
      expect(passwordReset.isLockedOut('jim@juice-sh.op')).to.equal(true)
    })

    it('unlocks an account after the lockout period', () => {
      for (let i = 0; i < passwordReset.MAX_FAILED_RESET_ATTEMPTS; i++) {
        passwordReset.registerFailedAttempt('jim@juice-sh.op')
      }
      clock.tick(passwordReset.RESET_LOCKOUT_MS + 1)
      expect(passwordReset.isLockedOut('jim@juice-sh.op')).to.equal(false)
    })

    it('clears failed attempts after a successful reset', () => {
      for (let i = 0; i < passwordReset.MAX_FAILED_RESET_ATTEMPTS - 1; i++) {
        passwordReset.registerFailedAttempt('jim@juice-sh.op')
      }
      passwordReset.clearFailedAttempts('jim@juice-sh.op')
      passwordReset.registerFailedAttempt('jim@juice-sh.op')
      expect(passwordReset.isLockedOut('jim@juice-sh.op')).to.equal(false)
    })
  })
})
