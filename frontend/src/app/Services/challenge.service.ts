/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { environment } from '../../environments/environment'
import { HttpClient } from '@angular/common/http'
import { Injectable, inject } from '@angular/core'
import { type Observable } from 'rxjs'
import { catchError, map } from 'rxjs/operators'
import { type Challenge } from '../Models/challenge.model'
import { SocketIoService } from './socket-io.service'

@Injectable({
  providedIn: 'root'
})
export class ChallengeService {
  private readonly http = inject(HttpClient)
  private readonly io = inject(SocketIoService)

  private readonly hostServer = environment.hostServer
  private readonly host = this.hostServer + '/api/Challenges'

  find (params?: any): Observable<Challenge[]> {
    return this.http.get(this.host + '/', { params }).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
  }

  repeatNotification (challengeName: string) {
    const params: Record<string, string> = { challenge: challengeName }
    const socketId = this.io.socket()?.id
    if (socketId) {
      params.socketId = socketId
    }
    return this.http.get(this.hostServer + '/rest/repeat-notification', { params, responseType: 'text' as const }).pipe(catchError((err) => { throw err }))
  }

  continueCode () {
    return this.http.get(this.hostServer + '/rest/continue-code').pipe(map((response: any) => response.continueCode), catchError((err) => { throw err }))
  }

  continueCodeFindIt () {
    return this.http.get(this.hostServer + '/rest/continue-code-findIt').pipe(map((response: any) => response.continueCode), catchError((err) => { throw err }))
  }

  continueCodeFixIt () {
    return this.http.get(this.hostServer + '/rest/continue-code-fixIt').pipe(map((response: any) => response.continueCode), catchError((err) => { throw err }))
  }

  restoreProgress (continueCode: string) {
    return this.http.put(this.hostServer + '/rest/continue-code/apply/' + continueCode, {}).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
  }

  restoreProgressFindIt (continueCode: string) {
    return this.http.put(this.hostServer + '/rest/continue-code-findIt/apply/' + continueCode, {}).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
  }

  restoreProgressFixIt (continueCode: string) {
    return this.http.put(this.hostServer + '/rest/continue-code-fixIt/apply/' + continueCode, {}).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
  }
}
