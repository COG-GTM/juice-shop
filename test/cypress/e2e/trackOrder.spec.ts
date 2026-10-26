describe('/#/track-order', () => {
  describe('challenge "reflectedXss"', () => {
    it('Order Id should be rendered as text instead of executing reflected XSS', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          const alertStub = cy.stub()
          cy.on('window:alert', alertStub)

          cy.visit('/#/track-result')
          cy.visit('/#/track-result?id=<iframe src="javascript:alert(`xss`)">')
          cy.reload()

          cy.get('h1 code').should('have.text', '<iframe src="javascript:alert(`xss`)">')
          cy.get('iframe').should('not.exist').then(() => {
            expect(alertStub).not.to.have.been.called
          })

          cy.expectChallengeSolved({ challenge: 'Reflected XSS' })
        }
      })
    })
  })
})
