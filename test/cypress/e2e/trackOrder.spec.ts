describe('/#/track-order', () => {
  describe('order id', () => {
    it('should render a reflected order id as text instead of HTML', () => {
      cy.on('window:alert', () => {
        throw new Error('Order id must not be rendered as HTML')
      })

      const payload = encodeURIComponent('<iframe src="javascript:alert(`xss`)">')
      cy.visit('/#/track-result?id=' + payload)

      cy.get('app-track-result h1 code').should('contain.text', 'iframesrcjavascriptalertxss')
      cy.get('app-track-result iframe').should('not.exist')
    })
  })
})
