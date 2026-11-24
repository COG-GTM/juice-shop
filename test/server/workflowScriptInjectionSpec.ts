/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'path'
import fs from 'fs'
import { load } from 'js-yaml'
import { expect } from 'chai'

const workflowsDir = path.resolve(__dirname, '../../.github/workflows')
const workflows = fs.readdirSync(workflowsDir).filter(file => file.endsWith('.yml')).map(file => ({ file, workflow: load(fs.readFileSync(path.join(workflowsDir, file), 'utf8')) as any }))

describe('workflows', () => {
  it('never interpolate branch or tag names into run scripts', () => {
    const offenders: string[] = []
    for (const { file, workflow } of workflows) {
      for (const [jobName, job] of Object.entries<any>(workflow.jobs ?? {})) {
        for (const step of job.steps ?? []) {
          if (typeof step.run === 'string' && /\$\{\{\s*github\.(ref_name|head_ref)\s*\}\}/.test(step.run)) {
            offenders.push(`${file}:${jobName}:${step.name ?? step.run.split('\n')[0]}`)
          }
        }
      }
    }
    expect(offenders).to.deep.equal([])
  })

  for (const file of ['update-challenges-www.yml', 'update-challenges-www-legacy.yml']) {
    it(`${file} only runs for the master and develop branches`, () => {
      const job = workflows.find(w => w.file === file)?.workflow.jobs.UpdateChallengesOnWebsite
      expect(job.if).to.contain("github.ref == 'refs/heads/master'")
      expect(job.if).to.contain("github.ref == 'refs/heads/develop'")
      expect(job.if).to.not.contain('github.ref_name')
    })
  }
})
