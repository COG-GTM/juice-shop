/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import http from 'node:http'
import { type AddressInfo } from 'node:net'
import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { profileImageUrlUpload, MAX_IMAGE_BYTES } from '../../routes/profileImageUrlUpload'
import { authenticatedUsers } from '../../lib/insecurity'
import { UserModel } from '../../models/user'
const expect = chai.expect
chai.use(sinonChai)

const uploadsDir = 'frontend/dist/frontend/assets/public/images/uploads'
const userId = 4711
const token = 'profileImageUrlUploadSpecToken'

describe('profileImageUrlUpload', () => {
  let server: http.Server
  let baseUrl: string
  let bytesServed: number
  let user: { update: sinon.SinonStub }
  let req: any
  let res: any
  let next: sinon.SinonSpy

  before(async () => {
    fs.mkdirSync(uploadsDir, { recursive: true })
    server = http.createServer((request, response) => {
      const chunk = Buffer.alloc(64 * 1024, 0xff)
      if (request.url === '/endless.png') {
        response.writeHead(200, { 'Content-Type': 'image/png' })
        const write = () => {
          while (!response.destroyed && response.write(chunk)) bytesServed += chunk.length
          if (!response.destroyed) response.once('drain', write)
        }
        write()
      } else if (request.url === '/huge.png') {
        response.writeHead(200, { 'Content-Type': 'image/png', 'Content-Length': String(MAX_IMAGE_BYTES * 1024) })
        response.write(chunk)
      } else if (request.url === '/slow.png') {
        response.writeHead(200, { 'Content-Type': 'image/png' })
        response.write(Buffer.alloc(16, 0xff))
      } else if (request.url === '/page.png') {
        response.writeHead(200, { 'Content-Type': 'text/html' })
        response.end('<html></html>')
      } else {
        response.writeHead(200, { 'Content-Type': 'image/png' })
        response.end(chunk)
      }
    })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  })

  after(() => {
    server.closeAllConnections()
    server.close()
  })

  beforeEach(() => {
    bytesServed = 0
    authenticatedUsers.put(token, { data: { id: userId } } as any)
    user = { update: sinon.stub().resolves() }
    sinon.stub(UserModel, 'findByPk').resolves(user as any)
    req = { body: {}, cookies: { token }, app: { locals: {} } }
    res = { location: sinon.spy(), redirect: sinon.spy() }
    next = sinon.spy()
  })

  afterEach(() => {
    sinon.restore()
    fs.rmSync(`${uploadsDir}/${userId}.png`, { force: true })
  })

  it('should store a small image fetched from the URL', async () => {
    req.body.imageUrl = `${baseUrl}/small.png`

    await profileImageUrlUpload()(req, res, next)

    expect(fs.statSync(`${uploadsDir}/${userId}.png`).size).to.equal(64 * 1024)
    expect(user.update).to.have.been.calledWith({ profileImage: `/assets/public/images/uploads/${userId}.png` })
    expect(res.redirect).to.have.been.calledWith(process.env.BASE_PATH + '/profile')
  })

  it('should stop downloading an endless image stream once the size limit is exceeded', async () => {
    req.body.imageUrl = `${baseUrl}/endless.png`

    await profileImageUrlUpload()(req, res, next)

    expect(bytesServed).to.be.below(MAX_IMAGE_BYTES * 8)
    expect(fs.existsSync(`${uploadsDir}/${userId}.png`)).to.equal(false)
    expect(user.update).to.have.been.calledWith({ profileImage: req.body.imageUrl })
    expect(res.redirect).to.have.been.calledWith(process.env.BASE_PATH + '/profile')
  })

  it('should not download an image whose Content-Length exceeds the size limit', async () => {
    req.body.imageUrl = `${baseUrl}/huge.png`

    await profileImageUrlUpload()(req, res, next)

    expect(fs.existsSync(`${uploadsDir}/${userId}.png`)).to.equal(false)
    expect(user.update).to.have.been.calledWith({ profileImage: req.body.imageUrl })
  })

  it('should abort a download that does not complete within the time limit', async () => {
    const timeout = AbortSignal.timeout.bind(AbortSignal)
    sinon.stub(AbortSignal, 'timeout').callsFake(() => timeout(200))
    req.body.imageUrl = `${baseUrl}/slow.png`

    await profileImageUrlUpload()(req, res, next)

    expect(fs.existsSync(`${uploadsDir}/${userId}.png`)).to.equal(false)
    expect(user.update).to.have.been.calledWith({ profileImage: req.body.imageUrl })
    expect(res.redirect).to.have.been.calledWith(process.env.BASE_PATH + '/profile')
  })

  it('should not download a response that is not an image', async () => {
    req.body.imageUrl = `${baseUrl}/page.png`

    await profileImageUrlUpload()(req, res, next)

    expect(fs.existsSync(`${uploadsDir}/${userId}.png`)).to.equal(false)
    expect(user.update).to.have.been.calledWith({ profileImage: req.body.imageUrl })
  })
})
