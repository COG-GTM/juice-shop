import chai from 'chai'
import sinonChai from 'sinon-chai'
import fs from 'node:fs'
import path from 'node:path'
import sinon from 'sinon'
import { checkVulnLines, getVerdict } from '../../routes/vulnCodeSnippet'
import { getCodeChallenges, getCodingChallengeInfoPath } from '../../lib/codingChallenges'
const expect = chai.expect
chai.use(sinonChai)

describe('vulnCodeSnippet', () => {
  it('should assert single correctly selected vuln line as correct', () => {
    expect(getVerdict([1], [], [1])).to.equal(true)
  })

  it('should assert multiple correctly selected vuln lines as correct in any order', () => {
    expect(getVerdict([1, 2], [], [1, 2])).to.equal(true)
    expect(getVerdict([1, 2], [], [2, 1])).to.equal(true)
    expect(getVerdict([1, 2, 3], [], [3, 1, 2])).to.equal(true)
  })

  it('should ignore selected neutral lines during correct assertion', () => {
    expect(getVerdict([1, 2], [3, 4], [1, 2, 3])).to.equal(true)
    expect(getVerdict([1, 2], [3, 4], [1, 2, 4])).to.equal(true)
    expect(getVerdict([1, 2], [3, 4], [1, 2, 3, 4])).to.equal(true)
  })

  it('should assert missing vuln lines as wrong', () => {
    expect(getVerdict([1, 2], [], [1])).to.equal(false)
    expect(getVerdict([1, 2], [], [2])).to.equal(false)
    expect(getVerdict([1, 2], [3], [2, 3])).to.equal(false)
    expect(getVerdict([1, 2], [3], [1, 3])).to.equal(false)
    expect(getVerdict([1, 2], [3, 4], [3, 4])).to.equal(false)
  })

  it('should assert additionally selected lines as wrong', () => {
    expect(getVerdict([1, 2], [], [1, 2, 3])).to.equal(false)
    expect(getVerdict([1, 2], [3], [1, 2, 3, 4])).to.equal(false)
  })

  it('should assert lack of selected lines as wrong', () => {
    expect(getVerdict([1, 2], [], [])).to.equal(false)
  })

  it('should assert empty edge case as correct', () => {
    expect(getVerdict([], [], [])).to.equal(true)
  })
})

describe('getCodingChallengeInfoPath', () => {
  const codefixesDir = path.resolve('./data/static/codefixes')

  it('should resolve a challenge key to its info file inside the codefixes directory', () => {
    expect(getCodingChallengeInfoPath('loginAdminChallenge')).to.equal(path.join(codefixesDir, 'loginAdminChallenge.info.yml'))
  })

  it('should reject keys escaping the codefixes directory', () => {
    expect(getCodingChallengeInfoPath('../../../package')).to.equal(null)
    expect(getCodingChallengeInfoPath('/etc/passwd')).to.equal(null)
  })

  it('should reject keys pointing into subdirectories', () => {
    expect(getCodingChallengeInfoPath('sub/loginAdminChallenge')).to.equal(null)
  })

  it('should reject non-string keys', () => {
    expect(getCodingChallengeInfoPath(['loginAdminChallenge'])).to.equal(null)
    expect(getCodingChallengeInfoPath({ key: 'loginAdminChallenge' })).to.equal(null)
    expect(getCodingChallengeInfoPath(undefined)).to.equal(null)
  })
})

describe('checkVulnLines', () => {
  const traversalKey = '../../../package'

  afterEach(async () => {
    sinon.restore()
    ;(await getCodeChallenges()).delete(traversalKey)
  })

  it('should not touch files outside the codefixes directory for a key with a code snippet', async () => {
    ;(await getCodeChallenges()).set(traversalKey, { snippet: '', vulnLines: [1], neutralLines: [] })
    const existsSync = sinon.spy(fs, 'existsSync')
    const readFileSync = sinon.spy(fs, 'readFileSync')
    const res: any = { __: (s: string) => s, status: sinon.stub().returnsThis(), json: sinon.stub().returnsThis() }

    await checkVulnLines()({ body: { key: traversalKey, selectedLines: [2] } } as any, res, () => {})

    expect(res.json).to.have.been.calledWithMatch({ verdict: false })
    const codefixesDir = path.resolve('./data/static/codefixes')
    for (const call of [...existsSync.getCalls(), ...readFileSync.getCalls()]) {
      expect(path.resolve(String(call.args[0])).startsWith(codefixesDir + path.sep)).to.equal(true)
    }
    expect(existsSync.getCalls().map(call => String(call.args[0]))).to.not.include('./data/static/codefixes/' + traversalKey + '.info.yml')
  })
})
