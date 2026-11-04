describe('/b2b/v2/order', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  it('should reject an infinite loop payload without evaluating it', () => {
    cy.window().then((win) => {
      cy.request({
        method: 'POST',
        url: '/b2b/v2/orders/',
        headers: { Authorization: `Bearer ${win.localStorage.getItem('token')}` },
        body: { orderLinesData: '(function dos() { while(true); })()' },
        failOnStatusCode: false
      }).its('status').should('eq', 400)
    })
  })

  it('should reject a recursive regular expression payload without evaluating it', () => {
    cy.window().then((win) => {
      cy.request({
        method: 'POST',
        url: '/b2b/v2/orders/',
        headers: { Authorization: `Bearer ${win.localStorage.getItem('token')}` },
        body: { orderLinesData: "/((a+)+)b/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaa')" },
        failOnStatusCode: false
      }).its('status').should('eq', 400)
    })
  })
})
