/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { environment } from 'src/environments/environment'
import { Injectable, NgZone, inject } from '@angular/core'
import io from 'socket.io-client'
type Socket = ReturnType<typeof io>

const tokenAuth = (cb: (data: object) => void) => { cb({ token: localStorage.getItem('token') }) }

@Injectable({
  providedIn: 'root'
})
export class SocketIoService {
  private readonly ngZone = inject(NgZone)

  private _socket: Socket

  constructor () {
    this.ngZone.runOutsideAngular(() => {
      if (environment.hostServer === '.') {
        this._socket = io(window.location.origin, {
          path: (window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/') + 'socket.io',
          auth: tokenAuth
        })
      } else {
        this._socket = io(environment.hostServer, { auth: tokenAuth })
      }
    })
  }

  socket () {
    return this._socket
  }

  reconnect () {
    this._socket.disconnect().connect()
  }
}
