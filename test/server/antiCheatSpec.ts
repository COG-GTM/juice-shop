import chai from 'chai'
import sinon from 'sinon'
import logger from '../../lib/logger'
import { type Challenge } from '../../data/types'
const expect = chai.expect

describe('antiCheat', () => {
  let antiCheat: any
  beforeEach(() => {
    delete require.cache[require.resolve('../../lib/antiCheat')]
    antiCheat = require('../../lib/antiCheat')
    antiCheat.reset()
  })

  describe('calculateCheatScore', () => {
    it('should return cheat score of 0 if challenge is tightly coupled to the previously solved one', () => {
      const challenge1: Challenge = { key: 'loginAdminChallenge', difficulty: 1 } as any
      const challenge2: Challenge = { key: 'weakPasswordChallenge', difficulty: 1 } as any

      antiCheat.calculateCheatScore(challenge1)
      const score = antiCheat.calculateCheatScore(challenge2)

      expect(score).to.equal(0)
    })

    it('should return cheat score of 0 if challenge is loosely coupled to the previously solved one', () => {
      const challenge1: Challenge = { key: 'localXssChallenge', difficulty: 1 } as any
      const challenge2: Challenge = { key: 'xssBonusChallenge', difficulty: 1 } as any

      antiCheat.calculateCheatScore(challenge1)
      const score = antiCheat.calculateCheatScore(challenge2)

      expect(score).to.equal(0)
    })

    it('should return cheat score of 0 if challenge is loosely coupled to one in the past', () => {
      const challenge1: Challenge = { key: 'localXssChallenge', difficulty: 1 } as any
      const challenge2: Challenge = { key: 'missingEncodingChallenge', difficulty: 1 } as any
      const challenge3: Challenge = { key: 'forgottenBackupChallenge', difficulty: 1 } as any
      const challenge4: Challenge = { key: 'xssBonusChallenge', difficulty: 1 } as any

      antiCheat.calculateCheatScore(challenge1)
      antiCheat.calculateCheatScore(challenge2)
      antiCheat.calculateCheatScore(challenge3)
      const score = antiCheat.calculateCheatScore(challenge4)

      expect(score).to.equal(0)
    })

    it('should assume cheating if two unrelated challenges are solved after each other', () => {
      const challenge1: Challenge = { key: 'localXssChallenge', difficulty: 1 } as any
      const challenge2: Challenge = { key: 'missingEncodingChallenge', difficulty: 1 } as any

      antiCheat.calculateCheatScore(challenge1)
      const score = antiCheat.calculateCheatScore(challenge2)

      expect(score).to.be.greaterThan(0)
    })
  })

  describe('cheat score logging', () => {
    let info: sinon.SinonStub
    beforeEach(() => {
      info = sinon.stub(logger, 'info')
    })
    afterEach(() => {
      info.restore()
    })

    it('should log the key of a known challenge', () => {
      antiCheat.calculateCheatScore({ key: 'leakedApiKeyChallenge', difficulty: 1 } as any)

      expect(info.lastCall.args[0]).to.contain('leakedApiKeyChallenge')
    })

    it('should not log a challenge key that is not part of the challenge catalog', () => {
      antiCheat.calculateCheatScore({ key: 'sk-live-0123456789abcdef', difficulty: 1 } as any)

      expect(info.lastCall.args[0]).to.not.contain('sk-live-0123456789abcdef')
      expect(info.lastCall.args[0]).to.contain('unknown challenge')
    })

    it('should not log a challenge key that is not part of the challenge catalog when cheating', () => {
      antiCheat.calculateCheatScore({ key: 'sk-live-0123456789abcdef', difficulty: 1 } as any, true)

      expect(info.lastCall.args[0]).to.not.contain('sk-live-0123456789abcdef')
      expect(info.lastCall.args[0]).to.contain('unknown challenge')
    })
  })
})
