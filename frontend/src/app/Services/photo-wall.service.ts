/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { environment } from '../../environments/environment'
import { Injectable, inject } from '@angular/core'
import { HttpClient, HttpParams } from '@angular/common/http'
import { catchError, map } from 'rxjs/operators'

@Injectable({
  providedIn: 'root'
})
export class PhotoWallService {
  private readonly http = inject(HttpClient)

  private readonly hostServer = environment.hostServer
  private readonly host = this.hostServer + '/rest/memories'

  addMemory (caption: string, image: File) {
    const postData = new FormData()
    postData.append('image', image, caption)
    postData.append('caption', caption)
    return this.http.post(this.host, postData).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
  }

  get () {
    return this.http.get(this.host + '/').pipe(map((response: any) => response.data), catchError((err: Error) => { throw err }))
  }

  getPage (limit: number, offset: number) {
    const params = new HttpParams().set('limit', limit).set('offset', offset)
    return this.http.get(this.host + '/', { params }).pipe(
      map((response: any) => ({ memories: response.data, total: response.meta?.total ?? response.data.length })),
      catchError((err: Error) => { throw err })
    )
  }
}
