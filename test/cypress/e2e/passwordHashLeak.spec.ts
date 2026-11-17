describe('challenge "Password Hash Leak"', () => {
  beforeEach(() => {
    cy.login({ email: 'admin@juice-sh.op', password: 'admin123' })
  })

  it('should not leak the password hash via fields parameter', () => {
    cy.request({
      method: 'GET',
      url: '/rest/user/whoami?fields=id,email,password'
    }).then((res) => {
      expect(res.body.user.email).to.equal('admin@juice-sh.op')
      expect(res.body.user).to.not.have.property('password')
    })
  })
})
