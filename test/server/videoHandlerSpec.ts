/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { getVideo, promotionVideo } from '../../routes/videoHandler'
const expect = chai.expect
chai.use(sinonChai)

const subtitlesFile = 'frontend/dist/frontend/assets/public/videos/owasp_promo.vtt'
const videoFile = 'frontend/dist/frontend/assets/public/videos/owasp_promo.mp4'
const xssPayload = '</script><script>alert(`xss`)</script>'

describe('videoHandler', () => {
  let req: any
  let res: any
  let next: any
  let stat: sinon.SinonStub
  let readFile: sinon.SinonStub

  beforeEach(() => {
    req = { headers: {} }
    res = { send: sinon.spy(), writeHead: sinon.spy() }
    next = sinon.spy()
    stat = sinon.stub(fs.promises, 'stat').callThrough()
    readFile = sinon.stub(fs.promises, 'readFile').callThrough()
    challenges.videoXssChallenge = { solved: false, save: () => ({ then () {} }) } as unknown as Challenge
  })

  afterEach(() => {
    sinon.restore()
  })

  function givenSubtitles (content: string) {
    readFile.withArgs(subtitlesFile, 'utf8').resolves(content as any)
  }

  describe('promotionVideo', () => {
    it('should embed the subtitles into the rendered page', async () => {
      givenSubtitles('WEBVTT\n\n00:00.000 --> 00:01.000\nJuice')

      await promotionVideo()(req, res, next)

      expect(next).to.have.callCount(0)
      expect(res.send).to.have.been.calledWith(sinon.match('<script id="subtitle" type="text/vtt" data-label="English" data-lang="en">WEBVTT\n\n00:00.000 --> 00:01.000\nJuice</script>'))
      expect(res.send).to.have.been.calledWith(sinon.match('<source src="./video" type="video/mp4">'))
    })

    it('should serve the cached page without recompiling the template while the subtitles are unchanged', async () => {
      givenSubtitles('WEBVTT cached')
      await promotionVideo()(req, res, next)
      readFile.resetHistory()

      await promotionVideo()(req, res, next)
      await promotionVideo()(req, res, next)

      expect(readFile).to.not.have.been.calledWith('views/promotionVideo.pug')
      expect(res.send).to.have.callCount(3)
      expect(res.send.secondCall.args[0]).to.equal(res.send.firstCall.args[0])
      expect(res.send.thirdCall.args[0]).to.equal(res.send.firstCall.args[0])
    })

    it('should re-render the page when the subtitles file is overwritten and solve "videoXssChallenge"', async () => {
      givenSubtitles('WEBVTT original')
      await promotionVideo()(req, res, next)
      expect(challenges.videoXssChallenge.solved).to.equal(false)

      givenSubtitles('WEBVTT\n\n00:00.000 --> 00:01.000\n' + xssPayload)
      await promotionVideo()(req, res, next)

      expect(res.send.secondCall.args[0]).to.contain(xssPayload)
      expect(res.send.secondCall.args[0]).to.not.contain('WEBVTT original')
      expect(challenges.videoXssChallenge.solved).to.equal(true)
    })

    it('should check "videoXssChallenge" on every request even when the page is cached', async () => {
      givenSubtitles(xssPayload)
      await promotionVideo()(req, res, next)
      challenges.videoXssChallenge.solved = false

      await promotionVideo()(req, res, next)

      expect(challenges.videoXssChallenge.solved).to.equal(true)
    })

    it('should re-render the page when the subtitles change without changing size or modification time', async () => {
      givenSubtitles('WEBVTT aaaa')
      await promotionVideo()(req, res, next)

      givenSubtitles('WEBVTT bbbb')
      await promotionVideo()(req, res, next)

      expect(res.send.secondCall.args[0]).to.contain('WEBVTT bbbb')
      expect(res.send.secondCall.args[0]).to.not.contain('WEBVTT aaaa')
    })

    it('should pass an error to the next handler when the subtitles file is missing', async () => {
      const error = new Error('ENOENT')
      readFile.withArgs(subtitlesFile, 'utf8').rejects(error)

      await promotionVideo()(req, res, next)

      expect(next).to.have.been.calledWith(error)
      expect(res.send).to.have.callCount(0)
    })
  })

  describe('getVideo', () => {
    it('should answer range requests with the requested slice of the video', async () => {
      stat.withArgs(videoFile).resolves({ size: 1000 } as any)
      const pipe = sinon.spy()
      const createReadStream = sinon.stub(fs, 'createReadStream').returns({ pipe } as any)
      req.headers.range = 'bytes=0-99'

      await getVideo()(req, res, next)

      expect(createReadStream).to.have.been.calledWith(videoFile, { start: 0, end: 99 })
      expect(res.writeHead).to.have.been.calledWith(206, sinon.match({ 'Content-Range': 'bytes 0-99/1000', 'Content-Length': 100 }))
      expect(pipe).to.have.been.calledWith(res)
    })

    it('should pass an error to the next handler when the video file is missing', async () => {
      const error = new Error('ENOENT')
      stat.withArgs(videoFile).rejects(error)

      await getVideo()(req, res, next)

      expect(next).to.have.been.calledWith(error)
      expect(res.writeHead).to.have.callCount(0)
    })
  })
})
