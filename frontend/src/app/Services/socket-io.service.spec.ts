/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TestBed } from '@angular/core/testing'

import { SocketIoService } from './socket-io.service'

describe('SocketIoService', () => {
    beforeEach(() => {
        TestBed.configureTestingModule({
            providers: [SocketIoService]
        })
    })

    it('should be created', () => {
        const service = TestBed.inject(SocketIoService)

        expect(service).toBeTruthy()
    })

    it('should send a persistent random client id in the handshake auth', () => {
        localStorage.removeItem('socketClientId')
        const service = TestBed.inject(SocketIoService)
        let data: any
        ;(service.socket() as any).auth((d: any) => { data = d })

        expect(data.clientId).toMatch(/^[a-f0-9]{32}$/)
        expect(localStorage.getItem('socketClientId')).toBe(data.clientId)
    })

    it('should reconnect with the current token after it changed', () => {
        localStorage.removeItem('token')
        const service = TestBed.inject(SocketIoService)
        const socket: any = service.socket()
        const disconnect = vi.spyOn(socket, 'disconnect')
        const connect = vi.spyOn(socket, 'connect')

        localStorage.setItem('token', 'TOKEN')
        service.socket()
        let data: any
        socket.auth((d: any) => { data = d })

        expect(disconnect).toHaveBeenCalled()
        expect(connect).toHaveBeenCalled()
        expect(data.token).toBe('TOKEN')
        localStorage.removeItem('token')
    })
})
