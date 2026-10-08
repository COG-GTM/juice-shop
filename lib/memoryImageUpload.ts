/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import multer from 'multer'
import { type Request, type Response, type NextFunction } from 'express'
import * as security from './insecurity'

export const MEMORY_IMAGE_MAX_BYTES = 200000

const uploadsDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads/')

const mimeTypeMap: Record<string, string> = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg'
}

const uploadToDisk = multer({
  storage: multer.diskStorage({
    destination: (req: Request, file: any, cb: any) => {
      const isValid = mimeTypeMap[file.mimetype]
      let error: Error | null = new Error('Invalid mime type')
      if (isValid) {
        error = null
      }
      cb(error, uploadsDir)
    },
    filename: (req: Request, file: any, cb: any) => {
      const name = security.sanitizeFilename(file.originalname)
        .toLowerCase()
        .split(' ')
        .join('-')
      const ext = mimeTypeMap[file.mimetype]
      cb(null, name + '-' + Date.now() + '.' + ext)
    }
  }),
  limits: { fileSize: MEMORY_IMAGE_MAX_BYTES, files: 1, fields: 5, parts: 6 }
})

export function uploadMemoryImage () {
  const single = uploadToDisk.single('image')
  return (req: Request, res: Response, next: NextFunction) => {
    single(req, res, (err?: unknown) => {
      if (err instanceof multer.MulterError) {
        res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ status: 'error', message: err.message })
        return
      }
      if (err) {
        next(err)
        return
      }
      const uploadedPath = req.file ? path.resolve(uploadsDir, path.basename(req.file.filename)) : undefined
      if (uploadedPath?.startsWith(uploadsDir + path.sep)) {
        res.on('finish', () => {
          if (res.statusCode >= 400) {
            fs.unlink(uploadedPath, () => {})
          }
        })
      }
      next()
    })
  }
}
