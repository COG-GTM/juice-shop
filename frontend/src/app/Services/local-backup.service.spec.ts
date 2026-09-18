/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TestBed } from '@angular/core/testing'
import { Subject, firstValueFrom, of, throwError } from 'rxjs'

import { LocalBackupService } from './local-backup.service'
import { CookieModule, CookieService } from 'ngy-cookie'
import { TranslateNoOpLoader, TranslateLoader, TranslateModule } from '@ngx-translate/core'
import { MatSnackBar } from '@angular/material/snack-bar'
import { ChallengeService } from './challenge.service'
import { SnackBarHelperService } from './snack-bar-helper.service'

describe('LocalBackupService', () => {
    let snackBar: any
    let cookieService: any
    let challengeService: any
    let action: Subject<void>

    beforeEach(() => {
        action = new Subject<void>()
        snackBar = {
            open: vi.fn().mockName("MatSnackBar.open")
        }
        snackBar.open.mockReturnValue(null)
        challengeService = {
            restoreProgress: vi.fn().mockName("ChallengeService.restoreProgress"),
            restoreProgressFindIt: vi.fn().mockName("ChallengeService.restoreProgressFindIt"),
            restoreProgressFixIt: vi.fn().mockName("ChallengeService.restoreProgressFixIt"),
            continueCode: vi.fn().mockName("ChallengeService.continueCode"),
            continueCodeFindIt: vi.fn().mockName("ChallengeService.continueCodeFindIt"),
            continueCodeFixIt: vi.fn().mockName("ChallengeService.continueCodeFixIt")
        }
        challengeService.continueCode.mockReturnValue(of('code'))
        challengeService.continueCodeFindIt.mockReturnValue(of('codeFindIt'))
        challengeService.continueCodeFixIt.mockReturnValue(of('codeFixIt'))
        challengeService.restoreProgress.mockReturnValue(of(true))
        challengeService.restoreProgressFindIt.mockReturnValue(of(true))
        challengeService.restoreProgressFixIt.mockReturnValue(of(true))

        TestBed.configureTestingModule({
            imports: [
                CookieModule.forRoot(),
                TranslateModule.forRoot({
                    loader: {
                        provide: TranslateLoader,
                        useClass: TranslateNoOpLoader
                    }
                })
            ],
            providers: [
                { provide: MatSnackBar, useValue: snackBar },
                { provide: ChallengeService, useValue: challengeService },
                CookieService,
                LocalBackupService
            ]
        })
        cookieService = TestBed.inject(CookieService)
    })

    afterEach(() => {
        vi.restoreAllMocks()
    })

    it('should be created', () => {
        const service = TestBed.inject(LocalBackupService)

        expect(service).toBeTruthy()
    })

    it('should save language to file', async () => {
        const service = TestBed.inject(LocalBackupService)
        const saveFileSpy = vi.spyOn(service, 'saveFile').mockImplementation(() => {})

        cookieService.put('language', 'de')
        await service.save()

        const blob = new Blob([JSON.stringify({ version: 1, language: 'de' })], { type: 'text/plain;charset=utf-8' })
        expect(saveFileSpy).toHaveBeenCalledWith(blob, `owasp_juice_shop-${new Date().toISOString().split('T')[0]}.json`)
    })

    it('should restore language from backup file', async () => {
        const service = TestBed.inject(LocalBackupService)
        cookieService.put('language', 'de')
        await firstValueFrom(service.restore(new File(['{ "version": 1, "language": "cn" }'], 'test.json')))
        expect(cookieService.get('language')).toBe('cn')
        expect(snackBar.open).toHaveBeenCalled()
    })

    it('should not restore language from an outdated backup version', async () => {
        const service = TestBed.inject(LocalBackupService)
        cookieService.put('language', 'de')
        await firstValueFrom(service.restore(new File(['{ "version": 0, "language": "cn" }'], 'test.json')))
        expect(cookieService.get('language')).toBe('de')
        expect(snackBar.open).toHaveBeenCalled()
    })

    it('should log and fallback to cookies when continue code retrieval fails during save', async () => {
        const service = TestBed.inject(LocalBackupService)
        const saveFileSpy = vi.spyOn(service, 'saveFile').mockImplementation(() => {})

        // ensure cookie fallback values exist
        cookieService.put('continueCode', 'C1')
        cookieService.put('continueCodeFindIt', 'C2')
        cookieService.put('continueCodeFixIt', 'C3')

        // simulate server failure for continue codes
        challengeService.continueCode.mockReturnValue(throwError('Error'))
        challengeService.continueCodeFindIt.mockReturnValue(throwError('Error'))
        challengeService.continueCodeFixIt.mockReturnValue(throwError('Error'))

        console.log = vi.fn()

        await service.save('test-backup')

        expect(console.log).toHaveBeenCalledWith('Failed to retrieve continue code(s) for backup from server. Using cookie values as fallback.')
        expect(saveFileSpy).toHaveBeenCalled()
    })

    it('should restore hacking progress with encoded continue codes and reload when the snackbar action is used', async () => {
        const service = TestBed.inject(LocalBackupService)
        const reload = mockLocationReload()
        snackBar.open.mockReturnValue({ onAction: () => action })

        await firstValueFrom(service.restore(new File([JSON.stringify({
            version: 1,
            continueCode: 'hack me',
            continueCodeFindIt: 'find me',
            continueCodeFixIt: 'fix me'
        })], 'test.json')))
        action.next()

        expect(challengeService.restoreProgress).toHaveBeenCalledWith('hack%20me')
        expect(challengeService.restoreProgressFindIt).toHaveBeenCalledWith('find%20me')
        expect(challengeService.restoreProgressFixIt).toHaveBeenCalledWith('fix%20me')
        expect(reload).toHaveBeenCalled()
    })

    it('should not restore progress for continue codes missing from the backup file', async () => {
        const service = TestBed.inject(LocalBackupService)
        const reload = mockLocationReload()
        snackBar.open.mockReturnValue({ onAction: () => action })

        await firstValueFrom(service.restore(new File([JSON.stringify({ version: 1, continueCode: 'code' })], 'test.json')))
        action.next()

        expect(challengeService.restoreProgress).toHaveBeenCalledWith('code')
        expect(challengeService.restoreProgressFindIt).not.toHaveBeenCalled()
        expect(challengeService.restoreProgressFixIt).not.toHaveBeenCalled()
        expect(reload).toHaveBeenCalled()
    })

    it('should log and not reload when restoring progress fails', async () => {
        const service = TestBed.inject(LocalBackupService)
        const reload = mockLocationReload()
        snackBar.open.mockReturnValue({ onAction: () => action })
        challengeService.restoreProgress.mockReturnValue(throwError(() => new Error('Error')))
        console.log = vi.fn()

        await firstValueFrom(service.restore(new File([JSON.stringify({ version: 1, continueCode: 'code' })], 'test.json')))
        action.next()

        expect(console.log).toHaveBeenCalledWith(new Error('Error'))
        expect(reload).not.toHaveBeenCalled()
    })

    it('should notify the user when the backup file cannot be parsed', async () => {
        const service = TestBed.inject(LocalBackupService)
        const helperSpy = vi.spyOn(TestBed.inject(SnackBarHelperService), 'open').mockImplementation(() => {})

        await firstValueFrom(service.restore(new File(['not json'], 'test.json')))

        expect(helperSpy).toHaveBeenCalledWith(expect.stringContaining('Backup restore operation failed: '), 'errorBar')
        expect(snackBar.open).not.toHaveBeenCalled()
    })

})

function mockLocationReload () {
    return vi.spyOn(Location.prototype, 'reload').mockImplementation(() => {})
}
