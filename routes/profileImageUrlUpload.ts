/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { once } from 'node:events'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import { assertSafeFetchUrl } from '../lib/urlSecurity'
import logger from '../lib/logger'

const IMAGE_EXTENSIONS_BY_CONTENT_TYPE: Record<string, string> = {
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'image/svg+xml': 'svg',
  'image/webp': 'webp'
}
const MAX_IMAGE_SIZE = 1024 * 1024 * 5
const FETCH_TIMEOUT = 5000

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        let filePath: string | undefined
        try {
          const safeUrl = await assertSafeFetchUrl(url)
          const response = await fetch(safeUrl, { redirect: 'manual', signal: AbortSignal.timeout(FETCH_TIMEOUT) })
          if (response.status >= 300 && response.status < 400) {
            throw new Error('url responded with a redirect which is not followed')
          }
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const contentType = (response.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase()
          const ext = IMAGE_EXTENSIONS_BY_CONTENT_TYPE[contentType]
          if (ext === undefined) {
            throw new Error(`url returned the non-image content type ${contentType}`)
          }
          filePath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`
          const fileStream = fs.createWriteStream(filePath, { flags: 'w' })
          try {
            let size = 0
            for await (const chunk of Readable.fromWeb(response.body as any)) {
              size += chunk.length
              if (size > MAX_IMAGE_SIZE) {
                throw new Error('url returned an image exceeding the maximum allowed size')
              }
              if (!fileStream.write(chunk)) {
                await once(fileStream, 'drain')
              }
            }
          } finally {
            fileStream.end()
          }
          await finished(fileStream)
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          if (filePath !== undefined) {
            await fs.promises.rm(filePath, { force: true }).catch(() => {})
          }
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
