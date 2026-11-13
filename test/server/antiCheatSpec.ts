import chai from 'chai'
import sinon from 'sinon'
import { type Challenge } from '../../data/types'
import logger from '../../lib/logger'
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
    let infoStub: sinon.SinonStub
    beforeEach(() => {
      infoStub = sinon.stub(logger, 'info')
    })
    afterEach(() => {
      infoStub.restore()
    })

    it('should not log challenge data when calculating a regular cheat score', () => {
      const challenge: Challenge = { key: 'resetPasswordJimChallenge', difficulty: 3 } as any

      antiCheat.calculateCheatScore(challenge)

      expect(infoStub.calledOnce).to.equal(true)
      expect(infoStub.firstCall.args[0]).to.match(/^Cheat score for challenge solved in \d+min/)
      expect(infoStub.firstCall.args[0]).to.not.include('resetPasswordJimChallenge')
    })

    it('should not log challenge data when a challenge was solved by cheating', () => {
      const challenge: Challenge = { key: 'changePasswordBenderChallenge', difficulty: 5 } as any

      antiCheat.calculateCheatScore(challenge, true)

      expect(infoStub.calledOnce).to.equal(true)
      expect(infoStub.firstCall.args[0]).to.match(/^Cheat score for challenge solved by using a bypass/)
      expect(infoStub.firstCall.args[0]).to.not.include('changePasswordBenderChallenge')
    })

    it('should not log challenge data when calculating a "Find it" cheat score', async () => {
      const challenge: Challenge = { key: 'resetPasswordJimChallenge' } as any

      await antiCheat.calculateFindItCheatScore(challenge)

      expect(infoStub.calledOnce).to.equal(true)
      expect(infoStub.firstCall.args[0]).to.match(/^Cheat score for "Find it" phase of challenge solved in \d+min/)
      expect(infoStub.firstCall.args[0]).to.not.include('resetPasswordJimChallenge')
    })

    it('should not log challenge data when calculating a "Fix it" cheat score', async () => {
      const challenge: Challenge = { key: 'resetPasswordJimChallenge' } as any

      await antiCheat.calculateFixItCheatScore(challenge)

      expect(infoStub.calledOnce).to.equal(true)
      expect(infoStub.firstCall.args[0]).to.match(/^Cheat score for "Fix it" phase of challenge solved in \d+min/)
      expect(infoStub.firstCall.args[0]).to.not.include('resetPasswordJimChallenge')
    })
  })
})
