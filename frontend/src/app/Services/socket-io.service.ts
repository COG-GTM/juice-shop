/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { environment } from 'src/environments/environment'
import { Injectable, NgZone, inject } from '@angular/core'
import io from 'socket.io-client'
type Socket = ReturnType<typeof io>

const CLIENT_ID_KEY = 'socketClientId'

@Injectable({
  providedIn: 'root'
})
export class SocketIoService {
  private readonly ngZone = inject(NgZone)

  private _socket: Socket
  private handshakeToken: string | null = localStorage.getItem('token')

  constructor () {
    this.ngZone.runOutsideAngular(() => {
      const auth = (cb: (data: object) => void) => {
        this.handshakeToken = localStorage.getItem('token')
        cb({ token: this.handshakeToken ?? undefined, clientId: this.clientId() })
      }
      if (environment.hostServer === '.') {
        this._socket = io(window.location.origin, {
          path: (window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/') + 'socket.io',
          auth
        } as any)
      } else {
        this._socket = io(environment.hostServer, { auth } as any)
      }
    })
  }

  socket () {
    if (localStorage.getItem('token') !== this.handshakeToken) {
      this.handshakeToken = localStorage.getItem('token')
      this.ngZone.runOutsideAngular(() => {
        this._socket.disconnect().connect()
      })
    }
    return this._socket
  }

  private clientId () {
    let clientId = localStorage.getItem(CLIENT_ID_KEY)
    if (!clientId || !/^[a-f0-9]{32}$/.test(clientId)) {
      const bytes = new Uint8Array(16)
      crypto.getRandomValues(bytes)
      clientId = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
      localStorage.setItem(CLIENT_ID_KEY, clientId)
    }
    return clientId
  }
}
