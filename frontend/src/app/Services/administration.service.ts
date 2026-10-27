/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { environment } from '../../environments/environment'
import { HttpClient } from '@angular/common/http'
import { Injectable, inject } from '@angular/core'
import { type Observable } from 'rxjs'
import { catchError, map, shareReplay } from 'rxjs/operators'

@Injectable({
  providedIn: 'root'
})
export class AdministrationService {
  private readonly http = inject(HttpClient)

  private readonly hostServer = environment.hostServer
  private readonly host = this.hostServer + '/rest/admin'

  private versionObservable?: Observable<string>

  getApplicationVersion (): Observable<string> {
    this.versionObservable ??= this.http.get(this.host + '/application-version').pipe(
      map((response: any) => response.version),
      catchError((error: Error) => {
        this.versionObservable = undefined
        throw error
      }),
      shareReplay({ bufferSize: 1, refCount: false })
    )
    return this.versionObservable
  }
}
