/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component, type OnInit, inject } from '@angular/core'
import { UntypedFormControl, UntypedFormGroup, Validators, FormsModule, ReactiveFormsModule } from '@angular/forms'
import { mimeType } from './mime-type.validator'
import { PhotoWallService } from '../Services/photo-wall.service'
import { ConfigurationService } from '../Services/configuration.service'
import { library } from '@fortawesome/fontawesome-svg-core'
import { faTwitter } from '@fortawesome/free-brands-svg-icons'
import { SnackBarHelperService } from '../Services/snack-bar-helper.service'
import { catchError } from 'rxjs/operators'
import { EMPTY } from 'rxjs'
import { MatInputModule } from '@angular/material/input'
import { MatFormFieldModule, MatLabel, MatError } from '@angular/material/form-field'
import { TranslateModule } from '@ngx-translate/core'
import { MatIconButton, MatButtonModule } from '@angular/material/button'
import { MatIconModule } from '@angular/material/icon'

import { MatCardModule, MatCardTitle, MatCardContent } from '@angular/material/card'
import { MatPaginatorModule, type PageEvent } from '@angular/material/paginator'

library.add(faTwitter)

@Component({
  selector: 'app-photo-wall',
  templateUrl: './photo-wall.component.html',
  styleUrls: ['./photo-wall.component.scss'],
  imports: [MatCardModule, MatIconModule, MatIconButton, MatCardTitle, TranslateModule, MatCardContent, FormsModule, ReactiveFormsModule, MatButtonModule, MatFormFieldModule, MatLabel, MatInputModule, MatError, MatPaginatorModule]
})
export class PhotoWallComponent implements OnInit {
  private readonly photoWallService = inject(PhotoWallService)
  private readonly configurationService = inject(ConfigurationService)
  private readonly snackBarHelperService = inject(SnackBarHelperService)

  public emptyState = true
  public imagePreview: string
  public form: UntypedFormGroup = new UntypedFormGroup({
    image: new UntypedFormControl('', { validators: [Validators.required], asyncValidators: [mimeType] }),
    caption: new UntypedFormControl('', [Validators.required])
  })

  public slideshowDataSource: { url: string, caption: string }[] = []
  public twitterHandle = null
  public pageSizeOptions = [12, 24, 48, 96]
  public pageSize = 24
  public pageIndex = 0
  public totalMemories = 0

  ngOnInit (): void {
    this.pageIndex = 0
    this.loadMemories()

    this.configurationService.getApplicationConfiguration().pipe(catchError(err => {
      console.log(err)

      return EMPTY
    })).subscribe((config) => {
      if (config?.application?.social) {
        if (config.application.social.twitterUrl) {
          this.twitterHandle = config.application.social.twitterUrl.replace('https://twitter.com/', '@')
        }
      }
    })
  }

  onPageChange (event: PageEvent) {
    this.pageSize = event.pageSize
    this.pageIndex = event.pageIndex
    this.loadMemories()
  }

  loadMemories () {
    this.photoWallService.getPage(this.pageSize, this.pageIndex * this.pageSize).pipe(catchError(err => {
      console.log(err)

      return EMPTY
    })).subscribe(({ memories, total }) => {
      this.totalMemories = total
      this.emptyState = total === 0
      this.slideshowDataSource = []
      for (const memory of memories) {
        if (memory.User?.username) {

          memory.caption = `${memory.caption} (© ${memory.User.username})`
        }
        this.slideshowDataSource.push({ url: memory.imagePath, caption: memory.caption })
      }
    })
  }

  onImagePicked (event: Event) {
    const file = (event.target as HTMLInputElement).files[0]
    this.form.patchValue({ image: file })
    this.form.get('image').updateValueAndValidity()
    const reader = new FileReader()
    reader.onload = () => {
      this.imagePreview = reader.result as string
    }
    reader.readAsDataURL(file)
  }

  save () {
    this.photoWallService.addMemory(this.form.value.caption, this.form.value.image).subscribe({
      next: () => {
        this.resetForm()
        this.ngOnInit()
        this.snackBarHelperService.open('IMAGE_UPLOAD_SUCCESS', 'confirmBar')
      },
      error: (err) => {
        this.snackBarHelperService.open(err.error?.error, 'errorBar')
        console.log(err)
      }
    })
  }

  isLoggedIn () {
    return localStorage.getItem('token')
  }

  resetForm () {
    this.form.get('image').setValue('')
    this.form.get('image').markAsPristine()
    this.form.get('image').markAsUntouched()
    this.form.get('caption').setValue('')
    this.form.get('caption').markAsPristine()
    this.form.get('caption').markAsUntouched()
    this.form.get('caption').setErrors(null)
  }
}
