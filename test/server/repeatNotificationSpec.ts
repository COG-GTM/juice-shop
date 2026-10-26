/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { type Challenge } from 'data/types'
import { challenges, notifications } from '../../data/datacache'
import { repeatNotification } from '../../routes/repeatNotification'

const expect = chai.expect
chai.use(sinonChai)

const globalWithSocketIO = global as typeof globalThis & { io: any }

describe('repeatNotification', () => {
  const originalChallenges = { ...challenges }

  after(() => {
    for (const key of Object.keys(challenges)) {
      delete challenges[key]
    }
    Object.assign(challenges, originalChallenges)
  })

  let req: any
  let res: any
  let originalIo: any

  beforeEach(() => {
    res = { sendStatus: sinon.spy() }
    originalIo = globalWithSocketIO.io
    globalWithSocketIO.io = { emit: sinon.spy() }
    notifications.length = 0
  })

  afterEach(() => {
    globalWithSocketIO.io = originalIo
    notifications.length = 0
  })

  it('should re-send notification for a solved challenge', () => {
    challenges.scoreBoardChallenge = { key: 'scoreBoardChallenge', name: 'Score Board', description: 'Find the <em>score board</em>.', solved: true } as unknown as Challenge
    req = { query: { challenge: encodeURIComponent('Score Board') } }

    repeatNotification()(req, res)

    expect(globalWithSocketIO.io.emit).to.have.been.calledWith('challenge solved', sinon.match({ key: 'scoreBoardChallenge', name: 'Score Board', challenge: 'Score Board (Find the score board.)', isRestore: true }))
    expect(res.sendStatus).to.have.been.calledWith(200)
  })

  it('should not send notification for an unsolved challenge', () => {
    challenges.scoreBoardChallenge = { key: 'scoreBoardChallenge', name: 'Score Board', solved: false } as unknown as Challenge
    req = { query: { challenge: 'Score Board' } }

    repeatNotification()(req, res)

    expect(globalWithSocketIO.io.emit).to.have.not.been.calledWith(sinon.match.any)
    expect(notifications).to.have.lengthOf(0)
    expect(res.sendStatus).to.have.been.calledWith(200)
  })

  it('should silently ignore unknown challenges', () => {
    req = { query: { challenge: 'Does Not Exist' } }

    repeatNotification()(req, res)

    expect(globalWithSocketIO.io.emit).to.have.not.been.calledWith(sinon.match.any)
    expect(res.sendStatus).to.have.been.calledWith(200)
  })
})
