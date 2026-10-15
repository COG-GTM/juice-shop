describe('/b2b/v2/order', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  const postOrder = (orderLinesData: string) => cy.window().then((win) => cy.request({
    method: 'POST',
    url: '/b2b/v2/orders/',
    headers: { Authorization: `Bearer ${win.localStorage.getItem('token')}` },
    body: { orderLinesData },
    failOnStatusCode: false
  }))

  describe('challenge "rce"', () => {
    it('an infinite loop deserialization payload should be rejected without being evaluated', () => {
      postOrder('(function dos() { while(true); })()').its('status').should('eq', 400)
      cy.request('/api/Challenges/?name=Blocked RCE DoS').its('body.data.0.solved').should('eq', false)
    })
  })

  describe('challenge "rceOccupy"', () => {
    it('a recursive regular expression payload should be rejected without causing a request timeout', () => {
      postOrder("/((a+)+)b/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaa')").its('status').should('eq', 400)
      cy.request('/api/Challenges/?name=Successful RCE DoS').its('body.data.0.solved').should('eq', false)
    })
  })

  it('order lines in documented JSON format should be accepted', () => {
    postOrder('[{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"}]').its('status').should('eq', 200)
  })
})
