describe('/#/track-order', () => {
  describe('order id', () => {
    it('should render a reflected order id as text instead of HTML', () => {
      cy.on('window:alert', () => {
        throw new Error('Order id must not be rendered as HTML')
      })

      cy.visit('/#/track-result?id=<iframe src="javascript:alert(`xss`)">')

      cy.get('app-track-result h1 code').should('contain.text', 'iframesrcjavascriptalertxss')
      cy.get('app-track-result iframe').should('not.exist')
    })
  })
})
