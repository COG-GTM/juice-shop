/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import fileType from 'file-type'

import logger from '../lib/logger'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

const uploadsDirectory = path.resolve('frontend/dist/frontend/assets/public/images/uploads')

export const allowedProfileImageTypes: Readonly<Record<string, string>> = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'image/webp': 'webp'
}

const uploadsInProgress = new Map<number, Promise<void>>()

async function serializePerUser (userId: number, task: () => Promise<void>) {
  const current = (uploadsInProgress.get(userId) ?? Promise.resolve()).then(task)
  const settled = current.catch(() => {})
  uploadsInProgress.set(userId, settled)
  try {
    await current
  } finally {
    if (uploadsInProgress.get(userId) === settled) uploadsInProgress.delete(userId)
  }
}

async function removeStaleProfileImages (userId: number, keepExtension: string) {
  await Promise.all(Object.values(allowedProfileImageTypes)
    .filter(ext => ext !== keepExtension)
    .map(async ext => { await fs.rm(path.join(uploadsDirectory, `${userId}.${ext}`), { force: true }) }))
}

export function profileImageFileUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const file = req.file
    const buffer = file?.buffer
    if (buffer === undefined) {
      res.status(500)
      next(new Error('Illegal file type'))
      return
    }
    const uploadedFileType = await fileType.fromBuffer(buffer)
    if (uploadedFileType === undefined) {
      res.status(500)
      next(new Error('Illegal file type'))
      return
    }
    const extension = allowedProfileImageTypes[uploadedFileType.mime]
    if (extension === undefined) {
      res.status(415)
      next(new Error(`Profile image upload does not accept this file type: ${uploadedFileType.mime}`))
      return
    }
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }
    const userId = Number(loggedInUser.data.id)
    if (!Number.isSafeInteger(userId) || userId < 1) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    const fileName = `${userId}.${extension}`
    let failed = false
    await serializePerUser(userId, async () => {
      let written = false
      try {
        await fs.writeFile(path.join(uploadsDirectory, fileName), buffer, { mode: 0o644 })
        written = true
      } catch (err) {
        logger.warn('Error writing file: ' + (err instanceof Error ? err.message : String(err)))
      }

      try {
        const user = await UserModel.findByPk(userId)
        if (user != null) {
          await user.update({ profileImage: `assets/public/images/uploads/${fileName}` })
        }
      } catch (error) {
        failed = true
        next(error)
        return
      }

      if (written) {
        try {
          await removeStaleProfileImages(userId, extension)
        } catch (err) {
          logger.warn('Error removing stale profile images: ' + (err instanceof Error ? err.message : String(err)))
        }
      }
    })
    if (failed) return
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
