/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import config from 'config'
import { EventEmitter } from 'events'
import type { Challenge } from 'data/types'
import { challenges, notifications } from '../../data/datacache'
import * as security from '../../lib/insecurity'
import {
  registerChallengeVerificationEvents,
  registerNotificationAcknowledgement,
  resetVerificationRateLimits,
  verifiedUserIdFrom,
  VERIFICATION_EVENT_LIMIT
} from '../../lib/startup/registerWebsocketEvents'
const expect = chai.expect

const localXssPayload = '<iframe src="javascript:alert(`xss`)">'

describe('registerWebsocketEvents', () => {
  let socket: EventEmitter & { id: string }
  let configGet: sinon.SinonStub
  let ctfMode: boolean

  const save = () => ({ then () {} })

  beforeEach(() => {
    resetVerificationRateLimits()
    socket = Object.assign(new EventEmitter(), { id: 'socket-1' })
    registerChallengeVerificationEvents(socket)
    registerNotificationAcknowledgement(socket)
    notifications.splice(0, notifications.length, { key: 'scoreBoardChallenge', flag: 'queued-flag' } as any)
    challenges.localXssChallenge = { solved: false, save } as unknown as Challenge
    challenges.xssBonusChallenge = { solved: false, save } as unknown as Challenge
    challenges.closeNotificationsChallenge = { solved: false, save } as unknown as Challenge
    ctfMode = true
    const originalGet = config.get.bind(config)
    configGet = sinon.stub(config, 'get').callsFake((key: string) => key === 'ctf.showFlagsInNotifications' ? ctfMode : originalGet(key))
  })

  afterEach(() => {
    configGet.restore()
    notifications.splice(0, notifications.length)
  })

  describe('verifiedUserIdFrom', () => {
    it('returns the user id of a validly signed token', () => {
      expect(verifiedUserIdFrom(security.authorize({ data: { id: 42 } }))).to.equal(42)
    })

    it('rejects missing, non-string and tampered tokens', () => {
      const [header, , signature] = security.authorize({ data: { id: 42 } }).split('.')
      const forgedPayload = Buffer.from(JSON.stringify({ data: { id: 1 } })).toString('base64url')
      expect(verifiedUserIdFrom(undefined)).to.equal(undefined)
      expect(verifiedUserIdFrom(null)).to.equal(undefined)
      expect(verifiedUserIdFrom(42)).to.equal(undefined)
      expect(verifiedUserIdFrom('')).to.equal(undefined)
      expect(verifiedUserIdFrom('not-a-token')).to.equal(undefined)
      expect(verifiedUserIdFrom(`${header}.${forgedPayload}.${signature}`)).to.equal(undefined)
    })
  })

  describe('in CTF mode', () => {
    it('ignores challenge verification events from unauthenticated sockets', () => {
      socket.emit('verifyLocalXssChallenge', localXssPayload)
      socket.emit('verifyCloseNotificationsChallenge', [{}, {}], 'not-a-token')

      expect(challenges.localXssChallenge.solved).to.equal(false)
      expect(challenges.closeNotificationsChallenge.solved).to.equal(false)
    })

    it('solves challenges for events carrying a valid login token', () => {
      const token = security.authorize({ data: { id: 42 } })
      socket.emit('verifyLocalXssChallenge', localXssPayload, token)
      socket.emit('verifyCloseNotificationsChallenge', [{}, {}], token)

      expect(challenges.localXssChallenge.solved).to.equal(true)
      expect(challenges.closeNotificationsChallenge.solved).to.equal(true)
    })

    it('rate-limits verification events per user', () => {
      const token = security.authorize({ data: { id: 42 } })
      for (let i = 0; i < VERIFICATION_EVENT_LIMIT; i++) {
        socket.emit('verifyLocalXssChallenge', 'harmless', token)
      }
      socket.emit('verifyLocalXssChallenge', localXssPayload, token)

      expect(challenges.localXssChallenge.solved).to.equal(false)
    })

    it('keeps queued notifications when an unauthenticated socket acknowledges them', () => {
      socket.emit('notification received', 'queued-flag')
      socket.emit('notification received', 'queued-flag', 'not-a-token')

      expect(notifications).to.have.lengthOf(1)
    })

    it('removes a queued notification acknowledged with a valid login token', () => {
      socket.emit('notification received', 'queued-flag', security.authorize({ data: { id: 42 } }))

      expect(notifications).to.have.lengthOf(0)
    })
  })

  describe('outside CTF mode', () => {
    beforeEach(() => { ctfMode = false })

    it('still solves challenges for anonymous sockets', () => {
      socket.emit('verifyLocalXssChallenge', localXssPayload)

      expect(challenges.localXssChallenge.solved).to.equal(true)
    })

    it('rate-limits anonymous verification events per socket', () => {
      for (let i = 0; i < VERIFICATION_EVENT_LIMIT; i++) {
        socket.emit('verifyCloseNotificationsChallenge', [])
      }
      socket.emit('verifyCloseNotificationsChallenge', [{}, {}])

      expect(challenges.closeNotificationsChallenge.solved).to.equal(false)
    })

    it('removes a queued notification acknowledged by an anonymous socket', () => {
      socket.emit('notification received', 'queued-flag')

      expect(notifications).to.have.lengthOf(0)
    })

    it('ignores non-string notification acknowledgements', () => {
      socket.emit('notification received', { flag: 'queued-flag' })

      expect(notifications).to.have.lengthOf(1)
    })
  })
})
