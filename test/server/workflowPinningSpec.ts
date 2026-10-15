/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import chai from 'chai'
import path from 'node:path'
import { safeLoad } from 'js-yaml'
const expect = chai.expect

describe('workflowPinning', () => {
  const workflow: any = safeLoad(fs.readFileSync(path.resolve('.github/workflows/image_actions.yml'), { encoding: 'utf8' }))

  it('should pin every action in the image compression workflow to a full commit SHA', () => {
    for (const job of Object.values<any>(workflow.jobs)) {
      for (const step of job.steps) {
        if (step.uses) {
          expect(step.uses, step.uses).to.match(/^[^@]+@[0-9a-f]{40}$/)
        }
      }
    }
  })

  it('should restrict GITHUB_TOKEN permissions in the image compression workflow', () => {
    expect(workflow.permissions).to.deep.equal({})
    for (const job of Object.values<any>(workflow.jobs)) {
      expect(job.permissions).to.deep.equal({ contents: 'write', 'pull-requests': 'write' })
    }
  })
})
