/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { ActivatedRoute, Router } from '@angular/router'
import { UserService } from '../Services/user.service'
import { CookieService } from 'ngy-cookie'
import { Component, NgZone, type OnInit, inject } from '@angular/core'
import { TranslateModule } from '@ngx-translate/core'
import { MatCardModule } from '@angular/material/card'

@Component({
  selector: 'app-oauth',
  templateUrl: './oauth.component.html',
  styleUrls: ['./oauth.component.scss'],
  imports: [MatCardModule, TranslateModule]
})
export class OAuthComponent implements OnInit {
  private readonly cookieService = inject(CookieService)
  private readonly userService = inject(UserService)
  private readonly router = inject(Router)
  private readonly route = inject(ActivatedRoute)
  private readonly ngZone = inject(NgZone)

  ngOnInit (): void {
    const params = this.parseRedirectUrlParams()
    const expectedState = sessionStorage.getItem('oauthState')
    sessionStorage.removeItem('oauthState')
    if (!expectedState || params.state !== expectedState) {
      this.invalidateSession(new Error('OAuth state mismatch'))
      this.ngZone.run(async () => await this.router.navigate(['/login']))
      return
    }
    this.userService.oauthLogin(params.access_token).subscribe({
      next: (authentication: any) => {
        const expires = new Date()
        expires.setHours(expires.getHours() + 8)
        this.cookieService.put('token', authentication.token, { expires })
        localStorage.setItem('token', authentication.token)
        sessionStorage.setItem('bid', authentication.bid)
        this.userService.isLoggedIn.next(true)
        this.ngZone.run(async () => await this.router.navigate(['/']))
      },
      error: (error) => {
        if (error.error?.status === 'totp_token_required') {
          localStorage.setItem('totp_tmp_token', error.error.data.tmpToken)
          this.ngZone.run(async () => await this.router.navigate(['/2fa/enter']))
          return
        }
        this.invalidateSession(error)
        this.ngZone.run(async () => await this.router.navigate(['/login']))
      }
    })
  }

  invalidateSession (error: Error) {
    console.log(error)
    this.cookieService.remove('token')
    localStorage.removeItem('token')
    sessionStorage.removeItem('bid')
  }

  parseRedirectUrlParams () {
    const hash = this.route.snapshot.data.params.substr(1)
    const splitted = hash.split('&')
    const params: any = {}
    for (const part of splitted) {
      const [key, value] = part.split('=')
      params[key] = value
    }
    return params
  }
}
