/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component, Directive, ElementRef, Injectable, Input, TemplateRef, contentChild, inject } from '@angular/core'
import { NgTemplateOutlet } from '@angular/common'

export class GalleryRef {
    items: any[] = []
    addImage (data: any) { this.items.push(data) }
    load (items: any[]) { this.items = items.map(item => item?.data ?? item) }
}

@Injectable({ providedIn: 'root' })
export class Gallery {
    private readonly refs = new Map<string, GalleryRef>()

    ref (id = 'root'): GalleryRef {
        if (!this.refs.has(id)) {
            this.refs.set(id, new GalleryRef())
        }
        return this.refs.get(id)
    }
}

@Directive({ selector: '[galleryImageDef]', standalone: true })
export class GalleryImageDef {
    readonly templateRef = inject(TemplateRef)
}

@Component({
    selector: 'gallery',
    template: '@for (item of galleryRef.items; track $index) {<ng-container *ngTemplateOutlet="imageDef()?.templateRef; context: { $implicit: item, active: $index === 0 }" />}',
    standalone: true,
    imports: [NgTemplateOutlet]
})
export class GalleryComponent {
    @Input() autoplay: boolean
    @Input() thumbs: boolean
    @Input() counter: boolean
    @Input() imageSize: string
    readonly imageDef = contentChild(GalleryImageDef)
    readonly galleryRef = inject(Gallery).ref(inject(ElementRef).nativeElement.id || undefined)
}
