describe('/#/track-order', () => {
  describe('challenge "reflectedXss"', () => {
    it('should render the reflected Order Id as text and still award the challenge', () => {
      const alertStub = cy.stub()
      cy.on('window:alert', alertStub)

      cy.visit('/#/track-result?id=<iframe src="javascript:alert(`xss`)">')
      cy.get('h1 code').should('contain.text', 'iframesrcjavascriptalertxss')
      cy.get('h1 iframe').should('not.exist')
      cy.wrap(alertStub).should('not.have.been.called')

      cy.expectChallengeSolved({ challenge: 'Reflected XSS' })
    })
  })
})
