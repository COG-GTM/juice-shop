/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { retrieveLoggedInUser } from '../../routes/currentUser'
import { authenticatedUsers } from '../../lib/insecurity'
import type { UserModel } from 'models/user'
const expect = chai.expect
chai.use(sinonChai)

describe('currentUser', () => {
  let req: any
  let res: any

  beforeEach(() => {
    req = { cookies: {}, query: {} }
    res = { json: sinon.spy() }
  })

  it('should return neither ID nor email if no cookie was present in the request headers', () => {
    req.cookies.token = ''

    retrieveLoggedInUser()(req, res)

    expect(res.json).to.have.been.calledWith({ user: { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined } })
  })

  it('should return ID and email of user belonging to cookie from the request', () => {
    req.cookies.token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImlkIjoxLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwibGFzdExvZ2luSXAiOiIwLjAuMC4wIiwicHJvZmlsZUltYWdlIjoiZGVmYXVsdC5zdmcifSwiaWF0IjoxNTgyMjIyMzY0fQ.CHiFQieZudYlrd1o8Ih-Izv7XY_WZupt8Our-CP9HqsczyEKqrWC7wWguOgVuSGDN_S3mP4FyuEFN8l60aAhVsUbqzFetvJkFwe5nKVhc9dHuen6cujQLMcTlHLKassOSDP41Q-MkKWcUOQu0xUkTMfEq2hPMHpMosDb4benzH0'
    req.query.callback = undefined
    authenticatedUsers.put(
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImlkIjoxLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwibGFzdExvZ2luSXAiOiIwLjAuMC4wIiwicHJvZmlsZUltYWdlIjoiZGVmYXVsdC5zdmcifSwiaWF0IjoxNTgyMjIyMzY0fQ.CHiFQieZudYlrd1o8Ih-Izv7XY_WZupt8Our-CP9HqsczyEKqrWC7wWguOgVuSGDN_S3mP4FyuEFN8l60aAhVsUbqzFetvJkFwe5nKVhc9dHuen6cujQLMcTlHLKassOSDP41Q-MkKWcUOQu0xUkTMfEq2hPMHpMosDb4benzH0',
      { data: { id: 1, email: 'admin@juice-sh.op', lastLoginIp: '0.0.0.0', profileImage: '/assets/public/images/uploads/default.svg' } as unknown as UserModel }
    )
    retrieveLoggedInUser()(req, res)

    expect(res.json).to.have.been.calledWith({ user: { id: 1, email: 'admin@juice-sh.op', lastLoginIp: '0.0.0.0', profileImage: '/assets/public/images/uploads/default.svg' } })
  })

  it('should not return sensitive fields even when requested', () => {
    req.cookies.token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImlkIjoxLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwibGFzdExvZ2luSXAiOiIwLjAuMC4wIiwicHJvZmlsZUltYWdlIjoiZGVmYXVsdC5zdmcifSwiaWF0IjoxNTgyMjIyMzY0fQ.CHiFQieZudYlrd1o8Ih-Izv7XY_WZupt8Our-CP9HqsczyEKqrWC7wWguOgVuSGDN_S3mP4FyuEFN8l60aAhVsUbqzFetvJkFwe5nKVhc9dHuen6cujQLMcTlHLKassOSDP41Q-MkKWcUOQu0xUkTMfEq2hPMHpMosDb4benzH0'
    req.query.fields = 'id,email,password,totpSecret'
    authenticatedUsers.tokenMap[req.cookies.token] = { data: { id: 1, email: 'admin@juice-sh.op', password: 'hash', totpSecret: 'SECRET' } as unknown as UserModel }
    retrieveLoggedInUser()(req, res)

    expect(res.json).to.have.been.calledWith({ user: { id: 1, email: 'admin@juice-sh.op' } })
  })

  it('should respond with plain JSON when a callback is requested', () => {
    req.cookies.token = ''
    req.query.callback = 'steal'
    res.jsonp = sinon.spy()

    retrieveLoggedInUser()(req, res)

    expect(res.json).to.have.been.calledWith({ user: { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined } })
    expect(res.jsonp.callCount).to.equal(0)
  })
})
