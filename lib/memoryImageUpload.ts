/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import multer from 'multer'
import { type Request, type Response, type NextFunction } from 'express'
import * as security from './insecurity'

export const MEMORY_IMAGE_MAX_BYTES = 200000
const MAX_NAME_BYTES = 200

const uploadsDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads/')

const mimeTypeMap: Record<string, string> = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg'
}

const imageSignatures: Record<string, number[]> = {
  png: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
  jpg: [0xFF, 0xD8, 0xFF]
}

function truncateToBytes (value: string, maxBytes: number) {
  let result = ''
  let bytes = 0
  for (const char of value) {
    bytes += Buffer.byteLength(char)
    if (bytes > maxBytes) break
    result += char
  }
  return result
}

export function hasImageSignature (filePath: string, ext: string) {
  const signature = imageSignatures[ext]
  if (signature === undefined) return false
  const header = Buffer.alloc(signature.length)
  const fd = fs.openSync(filePath, 'r')
  try {
    fs.readSync(fd, header, 0, signature.length, 0)
  } finally {
    fs.closeSync(fd)
  }
  return signature.every((byte, i) => header[i] === byte)
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
      const name = truncateToBytes(security.sanitizeFilename(file.originalname)
        .toLowerCase()
        .split(' ')
        .join('-'), MAX_NAME_BYTES)
      const ext = mimeTypeMap[file.mimetype]
      cb(null, name + '-' + Date.now() + '-' + crypto.randomBytes(8).toString('hex') + '.' + ext)
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
        if (!hasImageSignature(uploadedPath, mimeTypeMap[req.file?.mimetype ?? ''])) {
          fs.unlink(uploadedPath, () => {})
          res.status(400).json({ status: 'error', message: 'File content does not match its image type' })
          return
        }
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
