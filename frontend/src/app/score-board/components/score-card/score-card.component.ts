import { Component, Input, ChangeDetectionStrategy } from '@angular/core'
import { DecimalPipe } from '@angular/common'

@Component({
  selector: 'score-card',
  templateUrl: './score-card.component.html',
  styleUrls: ['./score-card.component.scss'],
  changeDetection: ChangeDetectionStrategy.Eager,
  imports: [DecimalPipe]
})
export class ScoreCardComponent {
  @Input()
  public description: string

  @Input()
  public total: number

  @Input()
  public score: number

  @Input()
  public showAsPercentage = true

  @Input()
  public showProgressBar = true
}
