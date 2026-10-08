/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import { Readable } from 'node:stream'
import { type Request, type Response, type NextFunction } from 'express'
import fileType from 'file-type'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const UPLOADS_DIR = 'frontend/dist/frontend/assets/public/images/uploads'
export const MAX_PROFILE_IMAGE_BYTES = 5 * 1024 * 1024
export const ALLOWED_PROFILE_IMAGE_TYPES: Record<string, string> = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif'
}

async function readBodyWithLimit (body: ReadableStream<Uint8Array>, limit: number): Promise<Buffer> {
  const stream = Readable.fromWeb(body as any)
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of stream) {
    size += chunk.length
    if (size > limit) {
      stream.destroy()
      throw new Error(`url returned more than ${limit} bytes`)
    }
    chunks.push(chunk)
  }
  return Buffer.concat(chunks)
}

export async function detectProfileImageExtension (buffer: Buffer): Promise<string> {
  const detected = await fileType.fromBuffer(buffer)
  const ext = detected ? ALLOWED_PROFILE_IMAGE_TYPES[detected.mime] : undefined
  if (ext === undefined) {
    throw new Error(`url did not return a JPG, PNG or GIF image${detected ? ' (detected ' + detected.mime + ')' : ''}`)
  }
  return ext
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const buffer = await readBodyWithLimit(response.body, MAX_PROFILE_IMAGE_BYTES)
          const ext = await detectProfileImageExtension(buffer)
          await fs.writeFile(`${UPLOADS_DIR}/${loggedInUser.data.id}.${ext}`, buffer)
          await fs.rm(`${UPLOADS_DIR}/${loggedInUser.data.id}.svg`, { force: true })
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
