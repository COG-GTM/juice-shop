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

    it('should log the registered key of a known challenge', () => {
      antiCheat.calculateCheatScore({ key: 'resetPasswordJimChallenge', difficulty: 3 } as any)
      antiCheat.calculateCheatScore({ key: 'changePasswordBenderChallenge', difficulty: 5 } as any, true)

      expect(info.firstCall.args[0]).to.contain('resetPasswordJimChallenge')
      expect(info.secondCall.args[0]).to.contain('changePasswordBenderChallenge')
    })

    it('should not log arbitrary values passed as challenge key', () => {
      antiCheat.calculateCheatScore({ key: 'admin123\nInjected log line', difficulty: 1 } as any)
      antiCheat.calculateCheatScore({ key: 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P', difficulty: 1 } as any, true)

      expect(info.callCount).to.equal(2)
      for (const call of info.getCalls()) {
        expect(call.args[0]).to.contain('unknown challenge')
        expect(call.args[0]).to.not.contain('admin123')
        expect(call.args[0]).to.not.contain('J6aVjTgOpRs')
      }
    })

    it('should log the registered key in the "Find it" and "Fix it" phases', async () => {
      await antiCheat.calculateFindItCheatScore({ key: 'loginAdminChallenge' } as any)
      await antiCheat.calculateFixItCheatScore({ key: 'loginAdminChallenge' } as any)

      expect(info.firstCall.args[0]).to.contain('"Find it" phase of').and.to.contain('loginAdminChallenge')
      expect(info.secondCall.args[0]).to.contain('"Fix it" phase of').and.to.contain('loginAdminChallenge')
    })

    it('should not log arbitrary values passed as challenge key in the "Fix it" phase', async () => {
      await antiCheat.calculateFixItCheatScore({ key: 'admin123\nInjected log line' } as any)

      expect(info.callCount).to.equal(1)
      expect(info.firstCall.args[0]).to.contain('unknown challenge')
      expect(info.firstCall.args[0]).to.not.contain('admin123')
    })
  })
})
