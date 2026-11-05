describe('/#/track-order', () => {
  describe('challenge "reflectedXss"', () => {
    it('Order Id payload should solve the challenge but be rendered as text', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          const payload = '<iframe src="javascript:alert(`xss`)">'
          cy.visit('/#/track-result?id=' + encodeURIComponent(payload))

          cy.get('h1 code').should('have.text', 'iframesrcjavascriptalertxss')
          cy.get('h1 iframe').should('not.exist')

          cy.expectChallengeSolved({ challenge: 'Reflected XSS' })
        }
      })
    })
  })
})
