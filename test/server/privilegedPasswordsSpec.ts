/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import chai from 'chai'
import { privilegedPasswordEnvVar, resolveUserPasswords } from '../../lib/privilegedPasswords'
const expect = chai.expect

describe('privilegedPasswords', () => {
  const envVars = ['JUICE_SHOP_ADMIN_PASSWORD', 'JUICE_SHOP_LET_US_TEST_PASSWORD', 'JUICE_SHOP_ACCOUNTANT_PASSWORD']
  let savedEnv: Record<string, string | undefined>
  let tmpDir: string
  let credentialsFile: string

  beforeEach(() => {
    savedEnv = {}
    for (const name of envVars) {
      savedEnv[name] = process.env[name]
      delete process.env[name]
    }
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'juice-shop-'))
    credentialsFile = path.join(tmpDir, 'privileged-credentials.txt')
  })

  afterEach(() => {
    for (const name of envVars) {
      if (savedEnv[name] === undefined) {
        delete process.env[name]
      } else {
        process.env[name] = savedEnv[name]
      }
    }
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  describe('privilegedPasswordEnvVar', () => {
    it('converts camelCase user keys into upper snake case environment variable names', () => {
      expect(privilegedPasswordEnvVar('admin')).to.equal('JUICE_SHOP_ADMIN_PASSWORD')
      expect(privilegedPasswordEnvVar('bjoernGoogle')).to.equal('JUICE_SHOP_BJOERN_GOOGLE_PASSWORD')
      expect(privilegedPasswordEnvVar('LetUsTest')).to.equal('JUICE_SHOP_LET_US_TEST_PASSWORD')
    })
  })

  describe('resolveUserPasswords', () => {
    it('keeps the static password of non-privileged users', () => {
      const passwords = resolveUserPasswords([
        { key: 'jim', role: 'customer', password: 'ncc-1701' },
        { key: 'ciso', role: 'deluxe', password: 'mDLx?94T~1CfVfZMzw@sJ9f?s3L6lbMqE70FfI8^54jbNikY5fymx7c!YbJb' }
      ], credentialsFile)
      expect(passwords.jim).to.equal('ncc-1701')
      expect(passwords.ciso).to.equal('mDLx?94T~1CfVfZMzw@sJ9f?s3L6lbMqE70FfI8^54jbNikY5fymx7c!YbJb')
      expect(fs.existsSync(credentialsFile)).to.equal(false)
    })

    it('generates a different random password for admin and accounting users on every start', () => {
      const users = [{ key: 'admin', role: 'admin' }, { key: 'accountant', role: 'accounting' }]
      const first = resolveUserPasswords(users, credentialsFile)
      const second = resolveUserPasswords(users, credentialsFile)
      expect(first.admin).to.match(/^[A-Za-z0-9_-]{24}$/)
      expect(first.accountant).to.match(/^[A-Za-z0-9_-]{24}$/)
      expect(first.admin).to.not.equal('admin123')
      expect(first.accountant).to.not.equal('i am an awesome accountant')
      expect(first.admin).to.not.equal(second.admin)
      expect(first.accountant).to.not.equal(second.accountant)
    })

    it('ignores any static password of privileged users', () => {
      const passwords = resolveUserPasswords([{ key: 'admin', role: 'admin', password: 'admin123' }], credentialsFile)
      expect(passwords.admin).to.not.equal('admin123')
    })

    it('writes generated passwords only to an owner-readable credentials file', () => {
      const passwords = resolveUserPasswords([{ key: 'admin', role: 'admin' }, { key: 'LetUsTest', role: 'admin' }], credentialsFile)
      expect(fs.readFileSync(credentialsFile, 'utf8')).to.equal(`JUICE_SHOP_ADMIN_PASSWORD=${passwords.admin}\nJUICE_SHOP_LET_US_TEST_PASSWORD=${passwords.LetUsTest}\n`)
      if (process.platform !== 'win32') {
        expect(fs.statSync(credentialsFile).mode & 0o777).to.equal(0o600)
      }
    })

    it('replaces an existing credentials file without keeping its permissions', () => {
      fs.writeFileSync(credentialsFile, 'stale', { mode: 0o644 })
      const passwords = resolveUserPasswords([{ key: 'admin', role: 'admin' }], credentialsFile)
      expect(fs.readFileSync(credentialsFile, 'utf8')).to.equal(`JUICE_SHOP_ADMIN_PASSWORD=${passwords.admin}\n`)
      if (process.platform !== 'win32') {
        expect(fs.statSync(credentialsFile).mode & 0o777).to.equal(0o600)
      }
    })

    it('fails instead of seeding unrecoverable passwords when the credentials file cannot be written', () => {
      expect(() => resolveUserPasswords([{ key: 'admin', role: 'admin' }], path.join(tmpDir, 'missing', 'privileged-credentials.txt'))).to.throw(/JUICE_SHOP_ADMIN_PASSWORD/)
    })

    it('uses the password from the environment variable of a privileged user', () => {
      process.env.JUICE_SHOP_ADMIN_PASSWORD = 'operator-chosen secret'
      const passwords = resolveUserPasswords([{ key: 'admin', role: 'admin' }], credentialsFile)
      expect(passwords.admin).to.equal('operator-chosen secret')
      expect(fs.existsSync(credentialsFile)).to.equal(false)
    })
  })
})
