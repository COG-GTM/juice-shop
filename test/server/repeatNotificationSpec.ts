/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import { type Request, type Response } from 'express'
import { repeatNotification } from '../../routes/repeatNotification'
import { challenges, notifications } from '../../data/datacache'
import { type Challenge } from 'data/types'

const expect = chai.expect
const globalWithSocketIO = global as typeof globalThis & { io: any }

describe('repeatNotification', () => {
  let socketEmit: sinon.SinonSpy
  let broadcastEmit: sinon.SinonSpy
  let to: sinon.SinonStub
  let res: Response
  let previousIo: any
  let previousChallenge: Challenge

  beforeEach(() => {
    previousIo = globalWithSocketIO.io
    socketEmit = sinon.spy()
    broadcastEmit = sinon.spy()
    to = sinon.stub().returns({ emit: socketEmit })
    globalWithSocketIO.io = { emit: broadcastEmit, to }
    res = { sendStatus: sinon.spy() } as unknown as Response
    notifications.splice(0, notifications.length)
    previousChallenge = challenges.scoreBoardChallenge
    challenges.scoreBoardChallenge = { key: 'scoreBoardChallenge', name: 'Repeat Me', description: 'x', solved: true } as unknown as Challenge
  })

  afterEach(() => {
    globalWithSocketIO.io = previousIo
    challenges.scoreBoardChallenge = previousChallenge
  })

  const call = (query: Record<string, string>) => { repeatNotification()({ query } as unknown as Request, res) }

  it('delivers the notification only to the requesting socket', () => {
    call({ challenge: 'Repeat Me', socketId: 'socket-1' })

    expect(to.calledOnceWith('socket-1')).to.equal(true)
    expect(socketEmit.calledOnce).to.equal(true)
    expect(socketEmit.firstCall.args[0]).to.equal('challenge solved')
    expect(socketEmit.firstCall.args[1].key).to.equal('scoreBoardChallenge')
    expect(broadcastEmit.called).to.equal(false)
    expect(notifications).to.have.lengthOf(0)
    expect((res.sendStatus as sinon.SinonSpy).calledOnceWith(200)).to.equal(true)
  })

  it('does nothing without a socketId however often it is called', () => {
    for (let i = 0; i < 1000; i++) {
      call({ challenge: 'Repeat Me' })
    }

    expect(to.called).to.equal(false)
    expect(broadcastEmit.called).to.equal(false)
    expect(notifications).to.have.lengthOf(0)
  })

  it('does not repeat an unsolved challenge', () => {
    challenges.scoreBoardChallenge.solved = false
    call({ challenge: 'Repeat Me', socketId: 'socket-1' })

    expect(to.called).to.equal(false)
    expect(broadcastEmit.called).to.equal(false)
  })
})
