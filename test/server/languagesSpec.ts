/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { getLanguageList } from '../../routes/languages'
const expect = chai.expect
chai.use(sinonChai)

describe('languages', () => {
  const originalCwd = process.cwd()
  let workDir: string
  let frontendDir: string
  let backendDir: string
  let res: any
  let next: any

  const writeJson = (dir: string, file: string, content: object) => {
    fs.writeFileSync(path.join(dir, file), JSON.stringify(content))
  }

  const fixedTime = new Date('2026-01-01T00:00:00Z')

  const pinMtime = (dir: string, action: () => void) => {
    action()
    fs.utimesSync(dir, fixedTime, fixedTime)
  }

  const touch = (file: string) => {
    fs.utimesSync(file, new Date(), new Date(Date.now() + 60000))
  }

  const languageKeys = () => res.json.lastCall.args[0].map((lang: { key: string }) => lang.key)

  beforeEach(() => {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'juice-shop-languages-'))
    frontendDir = path.join(workDir, 'frontend/dist/frontend/assets/i18n')
    backendDir = path.join(workDir, 'i18n')
    fs.mkdirSync(frontendDir, { recursive: true })
    fs.mkdirSync(backendDir)
    writeJson(frontendDir, 'en.json', { LANGUAGE: 'English', A: 'a', B: 'b' })
    writeJson(frontendDir, 'de_DE.json', { LANGUAGE: 'Deutsch', A: 'ä', B: 'b' })
    writeJson(frontendDir, 'tlh_AA.json', { LANGUAGE: 'tlhIngan', A: 'x', B: 'y' })
    writeJson(backendDir, 'en.json', { X: 'x', Y: 'y' })
    writeJson(backendDir, 'de_DE.json', { X: 'iks', Y: 'ypsilon' })
    fs.utimesSync(frontendDir, fixedTime, fixedTime)
    fs.utimesSync(backendDir, fixedTime, fixedTime)
    process.chdir(workDir)

    res = { status: sinon.stub().returnsThis(), json: sinon.spy() }
    next = sinon.spy()
  })

  afterEach(() => {
    process.chdir(originalCwd)
    fs.rmSync(workDir, { recursive: true, force: true })
  })

  it('should list all languages except Klingon sorted by name with averaged frontend and backend completion', async () => {
    await getLanguageList()({} as any, res, next)

    expect(next.callCount).to.equal(0)
    expect(res.status).to.have.been.calledWith(200)
    expect(res.json.lastCall.args[0]).to.deep.equal([
      { key: 'de_DE', lang: 'Deutsch', icons: ['de'], shortKey: 'DE', percentage: 83, gauge: 'full' },
      { key: 'en', icons: ['gb', 'us'], shortKey: 'EN', lang: 'English', percentage: 100, gauge: 'full' }
    ])
  })

  it('should not re-read translation files while their size and modification time are unchanged', async () => {
    const file = path.join(frontendDir, 'de_DE.json')
    fs.utimesSync(file, fixedTime, fixedTime)
    const handler = getLanguageList()
    await handler({} as any, res, next)

    pinMtime(frontendDir, () => { writeJson(frontendDir, 'de_DE.json', { LANGUAGE: 'Deutsc!', A: 'ä', B: 'b' }) })
    fs.utimesSync(file, fixedTime, fixedTime)
    await handler({} as any, res, next)

    expect(res.json.callCount).to.equal(2)
    expect(res.json.secondCall.args[0]).to.deep.equal(res.json.firstCall.args[0])
  })

  it('should recompute the list when a translation file is added to the frontend i18n folder', async () => {
    const handler = getLanguageList()
    await handler({} as any, res, next)
    expect(languageKeys()).to.deep.equal(['de_DE', 'en'])

    pinMtime(frontendDir, () => { writeJson(frontendDir, 'fr_FR.json', { LANGUAGE: 'Français', A: 'à', B: 'bé' }) })
    await handler({} as any, res, next)

    expect(languageKeys()).to.deep.equal(['de_DE', 'en', 'fr_FR'])
  })

  it('should recompute the list when a frontend translation file is edited in place', async () => {
    const handler = getLanguageList()
    await handler({} as any, res, next)

    pinMtime(frontendDir, () => { writeJson(frontendDir, 'de_DE.json', { LANGUAGE: 'Deutsch (neu)', A: 'ä', B: 'b' }) })
    touch(path.join(frontendDir, 'de_DE.json'))
    await handler({} as any, res, next)

    expect(res.json.lastCall.args[0][0].lang).to.equal('Deutsch (neu)')
  })

  it('should recompute the list when a translation file is replaced with one of the same size and modification time', async () => {
    const file = path.join(frontendDir, 'de_DE.json')
    fs.utimesSync(file, fixedTime, fixedTime)
    const handler = getLanguageList()
    await handler({} as any, res, next)

    const replacement = path.join(workDir, 'de_DE.json')
    writeJson(workDir, 'de_DE.json', { LANGUAGE: 'Deutsc!', A: 'ä', B: 'b' })
    fs.utimesSync(replacement, fixedTime, fixedTime)
    fs.renameSync(replacement, file)
    fs.utimesSync(frontendDir, new Date(), new Date(Date.now() + 60000))
    await handler({} as any, res, next)

    expect(res.json.lastCall.args[0][0].lang).to.equal('Deutsc!')
  })

  it('should recompute the list when a backend translation file is edited in place', async () => {
    const handler = getLanguageList()
    await handler({} as any, res, next)

    pinMtime(backendDir, () => { writeJson(backendDir, 'de_DE.json', { X: 'x', Y: 'y' }) })
    touch(path.join(backendDir, 'de_DE.json'))
    await handler({} as any, res, next)

    expect(res.json.lastCall.args[0][0].percentage).to.equal(33)
  })

  it('should not cache a failed computation', async () => {
    const handler = getLanguageList()
    pinMtime(frontendDir, () => { fs.rmSync(path.join(frontendDir, 'en.json')) })
    await handler({} as any, res, next)

    expect(next.callCount).to.equal(1)
    expect(res.json.callCount).to.equal(0)

    pinMtime(frontendDir, () => { writeJson(frontendDir, 'en.json', { LANGUAGE: 'English', A: 'a', B: 'b' }) })
    await handler({} as any, res, next)

    expect(next.callCount).to.equal(1)
    expect(languageKeys()).to.deep.equal(['de_DE', 'en'])
  })
})
