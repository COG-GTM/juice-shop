/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { randomUUID } from 'node:crypto'
import { Readable, Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export const MAX_IMAGE_BYTES = 200000
export const DOWNLOAD_TIMEOUT_MS = 10000

function byteLimit (maxBytes: number) {
  let received = 0
  return new Transform({
    transform (chunk: Buffer, _encoding, callback) {
      received += chunk.length
      if (received > maxBytes) {
        callback(new Error(`image exceeds the maximum size of ${maxBytes} bytes`))
        return
      }
      callback(null, chunk)
    }
  })
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetch(url, { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS) })
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          if (!(response.headers.get('content-type') ?? '').toLowerCase().startsWith('image/')) {
            await response.body.cancel()
            throw new Error('url did not return an image content type')
          }
          if (Number(response.headers.get('content-length') ?? 0) > MAX_IMAGE_BYTES) {
            await response.body.cancel()
            throw new Error(`image exceeds the maximum size of ${MAX_IMAGE_BYTES} bytes`)
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const filePath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`
          const tempPath = `${filePath}.${randomUUID()}.part`
          try {
            await pipeline(Readable.fromWeb(response.body as any), byteLimit(MAX_IMAGE_BYTES), fs.createWriteStream(tempPath, { flags: 'wx' }))
            await fs.promises.rename(tempPath, filePath)
          } catch (error) {
            await fs.promises.rm(tempPath, { force: true })
            throw error
          }
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
