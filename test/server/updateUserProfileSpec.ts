/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import sinonChai from 'sinon-chai'
import { challenges } from '../../data/datacache'
import type { Challenge } from 'data/types'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'
import { updateUserProfile } from '../../routes/updateUserProfile'
const expect = chai.expect

chai.use(sinonChai)

describe('updateUserProfile', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    security.authenticatedUsers.put('token12345', { data: { id: 42 } } as any)
    sinon.stub(UserModel, 'findByPk').resolves({
      username: 'bjoern',
      update: sinon.stub().rejects(new Error('update skipped'))
    } as any)
    challenges.csrfChallenge = { solved: false, save: () => ({ then () { } }) } as unknown as Challenge
    req = { cookies: { token: 'token12345' }, body: { username: 'CSRF' }, headers: {}, socket: {} }
    res = {}
    next = sinon.spy()
  })

  afterEach(() => {
    sinon.restore()
  })

  describe('"csrfChallenge"', () => {
    it('is solved when the username is changed from the htmledit.squarefree.com origin', async () => {
      req.headers.origin = 'http://htmledit.squarefree.com'

      await updateUserProfile()(req, res, next)

      expect(challenges.csrfChallenge.solved).to.equal(true)
    })

    it('is solved when the username is changed with a htmledit.squarefree.com referer and no origin', async () => {
      req.headers.referer = 'https://htmledit.squarefree.com/'

      await updateUserProfile()(req, res, next)

      expect(challenges.csrfChallenge.solved).to.equal(true)
    })

    it('is not solved when the username stays the same', async () => {
      req.headers.origin = 'http://htmledit.squarefree.com'
      req.body.username = 'bjoern'

      await updateUserProfile()(req, res, next)

      expect(challenges.csrfChallenge.solved).to.equal(false)
    })

    for (const source of [
      'http://attacker.com/?://htmledit.squarefree.com',
      'http://attacker.com#://htmledit.squarefree.com',
      'http://htmledit.squarefree.com.attacker.com',
      'http://htmledit.squarefree.com@attacker.com',
    'http://htmledit.squarefree.com:1234',
      'null',
      'htmledit.squarefree.com'
    ]) {
      it(`is not solved for origin "${source}"`, async () => {
        req.headers.origin = source

        await updateUserProfile()(req, res, next)

        expect(challenges.csrfChallenge.solved).to.equal(false)
      })

      it(`is not solved for referer "${source}"`, async () => {
        req.headers.referer = source

        await updateUserProfile()(req, res, next)

        expect(challenges.csrfChallenge.solved).to.equal(false)
      })
    }
  })
})
