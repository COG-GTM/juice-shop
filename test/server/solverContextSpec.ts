/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import crypto from 'node:crypto'
import chai from 'chai'
import * as security from '../../lib/insecurity'
import * as solverContext from '../../lib/solverContext'

const expect = chai.expect

const base64url = (input: string | Buffer) => Buffer.from(input).toString('base64url')
const unsignedToken = (payload: object) => `${base64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${base64url(JSON.stringify(payload))}.`
const hmacToken = (payload: object) => {
  const signingInput = `${base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${base64url(JSON.stringify(payload))}`
  const signature = crypto.createHmac('sha256', fs.readFileSync('encryptionkeys/jwt.pub', 'utf8')).update(signingInput).digest()
  return `${signingInput}.${base64url(signature)}`
}

describe('solverContext', () => {
  describe('userIdFromToken', () => {
    it('returns the user id of a regularly signed token', () => {
      expect(solverContext.userIdFromToken(security.authorize({ data: { id: 7 } }))).to.equal(7)
    })

    it('ignores missing or malformed tokens', () => {
      expect(solverContext.userIdFromToken(undefined)).to.equal(undefined)
      expect(solverContext.userIdFromToken('')).to.equal(undefined)
      expect(solverContext.userIdFromToken('not-a-jwt')).to.equal(undefined)
      expect(solverContext.userIdFromToken({ data: { id: 1 } })).to.equal(undefined)
    })

    it('ignores unsigned tokens', () => {
      expect(solverContext.userIdFromToken(unsignedToken({ data: { id: 1 }, exp: 9999999999 }))).to.equal(undefined)
    })

    it('ignores tokens HMAC-signed with the public key', () => {
      expect(solverContext.userIdFromToken(hmacToken({ data: { id: 1 }, exp: 9999999999 }))).to.equal(undefined)
    })

    it('ignores tokens with a tampered payload', () => {
      const [header, , signature] = security.authorize({ data: { id: 7 } }).split('.')
      expect(solverContext.userIdFromToken(`${header}.${base64url(JSON.stringify({ data: { id: 1 } }))}.${signature}`)).to.equal(undefined)
    })

    it('ignores expired tokens', () => {
      expect(solverContext.userIdFromToken(security.authorize({ data: { id: 7 }, exp: 1 }))).to.equal(undefined)
    })
  })

  describe('tokenFromCookieHeader', () => {
    it('extracts the token cookie', () => {
      expect(solverContext.tokenFromCookieHeader('language=en; token=abc.def.ghi; welcomebanner_status=dismiss')).to.equal('abc.def.ghi')
    })

    it('returns undefined without token cookie', () => {
      expect(solverContext.tokenFromCookieHeader('language=en')).to.equal(undefined)
      expect(solverContext.tokenFromCookieHeader(undefined)).to.equal(undefined)
    })
  })

  describe('currentSolverId', () => {
    it('is undefined outside of a request', () => {
      expect(solverContext.currentSolverId()).to.equal(undefined)
    })

    it('resolves the user from the bearer token of the current request', (done) => {
      const req: any = { headers: { authorization: `Bearer ${security.authorize({ data: { id: 3 } })}` } }
      solverContext.middleware()(req, {} as any, () => {
        setImmediate(() => {
          expect(solverContext.currentSolverId()).to.equal(3)
          done()
        })
      })
    })

    it('resolves the user from the token cookie of the current request', (done) => {
      const req: any = { headers: { cookie: `token=${security.authorize({ data: { id: 4 } })}` } }
      solverContext.middleware()(req, {} as any, () => {
        expect(solverContext.currentSolverId()).to.equal(4)
        done()
      })
    })

    it('is undefined for an anonymous request', (done) => {
      solverContext.middleware()({ headers: {} } as any, {} as any, () => {
        expect(solverContext.currentSolverId()).to.equal(undefined)
        done()
      })
    })

    it('uses the user given to runAs', () => {
      expect(solverContext.runAs(5, () => solverContext.currentSolverId())).to.equal(5)
      expect(solverContext.runAs(undefined, () => solverContext.currentSolverId())).to.equal(undefined)
    })
  })
})
