/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { retrieveLoggedInUser } from '../../routes/currentUser'
import { authenticatedUsers } from '../../lib/insecurity'
import { challenges } from '../../data/datacache'
import type { Challenge } from 'data/types'
import type { UserModel } from 'models/user'
const expect = chai.expect
chai.use(sinonChai)

describe('currentUser', () => {
  const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImlkIjoxLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwibGFzdExvZ2luSXAiOiIwLjAuMC4wIiwicHJvZmlsZUltYWdlIjoiZGVmYXVsdC5zdmcifSwiaWF0IjoxNTgyMjIyMzY0fQ.CHiFQieZudYlrd1o8Ih-Izv7XY_WZupt8Our-CP9HqsczyEKqrWC7wWguOgVuSGDN_S3mP4FyuEFN8l60aAhVsUbqzFetvJkFwe5nKVhc9dHuen6cujQLMcTlHLKassOSDP41Q-MkKWcUOQu0xUkTMfEq2hPMHpMosDb4benzH0'
  const save = () => ({
    then () { }
  })
  let req: any
  let res: any

  beforeEach(() => {
    req = { cookies: {}, query: {} }
    res = { json: sinon.spy(), jsonp: sinon.spy() }
  })

  it('should return neither ID nor email if no cookie was present in the request headers', () => {
    req.cookies.token = ''

    retrieveLoggedInUser()(req, res)

    expect(res.json).to.have.been.calledWith({ user: { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined } })
  })

  it('should return ID and email of user belonging to cookie from the request', () => {
    req.cookies.token = token
    req.query.callback = undefined
    authenticatedUsers.put(
      token,
      { data: { id: 1, email: 'admin@juice-sh.op', lastLoginIp: '0.0.0.0', profileImage: '/assets/public/images/uploads/default.svg' } as unknown as UserModel }
    )
    retrieveLoggedInUser()(req, res)

    expect(res.json).to.have.been.calledWith({ user: { id: 1, email: 'admin@juice-sh.op', lastLoginIp: '0.0.0.0', profileImage: '/assets/public/images/uploads/default.svg' } })
  })

  it('should return only the requested fields when a fields parameter is given', () => {
    req.cookies.token = token
    req.query.fields = 'email'
    authenticatedUsers.put(
      token,
      { data: { id: 1, email: 'admin@juice-sh.op', lastLoginIp: '0.0.0.0', profileImage: '/assets/public/images/uploads/default.svg' } as unknown as UserModel }
    )

    retrieveLoggedInUser()(req, res)

    expect(res.json).to.have.been.calledWith({ user: { email: 'admin@juice-sh.op' } })
  })

  it('should ignore requested fields not present on the user', () => {
    req.cookies.token = token
    req.query.fields = 'id, doesNotExist'
    authenticatedUsers.put(
      token,
      { data: { id: 1, email: 'admin@juice-sh.op', lastLoginIp: '0.0.0.0', profileImage: '/assets/public/images/uploads/default.svg' } as unknown as UserModel }
    )

    retrieveLoggedInUser()(req, res)

    expect(res.json).to.have.been.calledWith({ user: { id: 1 } })
  })

  it('should solve "passwordHashLeakChallenge" when the password field is requested', () => {
    challenges.passwordHashLeakChallenge = { solved: false, save } as unknown as Challenge
    req.cookies.token = token
    req.query.fields = 'id,password'
    authenticatedUsers.put(
      token,
      { data: { id: 1, email: 'admin@juice-sh.op', password: '0192023a7bbd73250516f069df18b500', lastLoginIp: '0.0.0.0', profileImage: '/assets/public/images/uploads/default.svg' } as unknown as UserModel }
    )

    retrieveLoggedInUser()(req, res)

    expect(res.json).to.have.been.calledWith({ user: { id: 1, password: '0192023a7bbd73250516f069df18b500' } })
    expect(challenges.passwordHashLeakChallenge.solved).to.equal(true)
  })

  it('should not solve "passwordHashLeakChallenge" for the default field set', () => {
    challenges.passwordHashLeakChallenge = { solved: false, save } as unknown as Challenge
    req.cookies.token = token
    authenticatedUsers.put(
      token,
      { data: { id: 1, email: 'admin@juice-sh.op', password: '0192023a7bbd73250516f069df18b500', lastLoginIp: '0.0.0.0', profileImage: '/assets/public/images/uploads/default.svg' } as unknown as UserModel }
    )

    retrieveLoggedInUser()(req, res)

    expect(challenges.passwordHashLeakChallenge.solved).to.equal(false)
  })

  it('should respond with JSONP and solve "emailLeakChallenge" when a callback is given', () => {
    challenges.emailLeakChallenge = { solved: false, save } as unknown as Challenge
    req.cookies.token = token
    req.query.callback = 'callbackFunction'
    authenticatedUsers.put(
      token,
      { data: { id: 1, email: 'admin@juice-sh.op', lastLoginIp: '0.0.0.0', profileImage: '/assets/public/images/uploads/default.svg' } as unknown as UserModel }
    )

    retrieveLoggedInUser()(req, res)

    expect(res.json).to.have.not.been.called
    expect(res.jsonp).to.have.been.calledWith({ user: { id: 1, email: 'admin@juice-sh.op', lastLoginIp: '0.0.0.0', profileImage: '/assets/public/images/uploads/default.svg' } })
    expect(challenges.emailLeakChallenge.solved).to.equal(true)
  })
})
