/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import yaml from 'js-yaml'
import { expect } from 'chai'

describe('ciWorkflow', () => {
  const workflow: any = yaml.load(fs.readFileSync('.github/workflows/ci.yml', 'utf8'))

  it('should pin every third-party action to a full commit hash', () => {
    for (const [jobName, job] of Object.entries<any>(workflow.jobs)) {
      for (const step of job.steps ?? []) {
        if (step.uses !== undefined && !String(step.uses).startsWith('./')) {
          expect(step.uses, `${jobName}: ${step.name}`).to.match(/@[0-9a-f]{40}$/)
        }
      }
    }
  })

  it('should limit the token handed to the Coveralls upload to read-only repository contents', () => {
    expect(workflow.jobs['coverage-report'].permissions).to.deep.equal({ contents: 'read' })
  })
})
