/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component, inject, OnInit } from '@angular/core'
import { DomSanitizer } from '@angular/platform-browser'
import { TranslateModule } from '@ngx-translate/core'
import { MatCardModule } from '@angular/material/card'
import { sessionClaims } from '../Services/auth-session'

@Component({
  selector: 'app-last-login-ip',
  templateUrl: './last-login-ip.component.html',
  styleUrls: ['./last-login-ip.component.scss'],
  imports: [MatCardModule, TranslateModule]
})

export class LastLoginIpComponent implements OnInit {
  private readonly sanitizer = inject(DomSanitizer)

  lastLoginIp: any = '?'

  ngOnInit (): void {
    try {
      this.parseAuthToken()
    } catch (err) {
      console.log(err)
    }
  }

  parseAuthToken () {
    const lastLoginIp = sessionClaims()?.data.lastLoginIp
    if (lastLoginIp) {

      this.lastLoginIp = this.sanitizer.bypassSecurityTrustHtml(`<small>${lastLoginIp}</small>`)
    }
  }
}
