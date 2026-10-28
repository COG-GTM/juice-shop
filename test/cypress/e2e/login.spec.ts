describe('/#/login', () => {
  beforeEach(() => {
    cy.visit('/#/login')
  })

  describe('SQL injection authentication bypass', () => {
    const payloads = [
      "' or 1=1--",
      "admin@juice-sh.op'--",
      "jim@juice-sh.op'--",
      "bender@juice-sh.op'--",
      "wurstbrot@juice-sh.op'--",
      "chris.pike@juice-sh.op'--",
      "' or deletedAt IS NOT NULL--",
      "' UNION SELECT * FROM (SELECT 15 as 'id', '' as 'username', 'acc0unt4nt@juice-sh.op' as 'email', '12345' as 'password', 'accounting' as 'role', '123' as 'deluxeToken', '1.2.3.4' as 'lastLoginIp' , '/assets/public/images/uploads/default.svg' as 'profileImage', '' as 'totpSecret', 1 as 'isActive', '1999-08-16 14:14:41.644 +00:00' as 'createdAt', '1999-08-16 14:33:41.930 +00:00' as 'updatedAt', null as 'deletedAt')--"
    ]

    payloads.forEach((payload) => {
      it(`should reject login with SQLI payload "${payload}" and a wrong password`, () => {
        cy.get('#email').type(payload)
        cy.get('#password').type('a')
        cy.get('#loginButton').click()
        cy.get('.error').should('contain', 'Invalid email or password.')
      })
    })
  })

  describe('challenge "adminCredentials"', () => {
    it('should be able to log in with original (weak) admin credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`admin@${appDomain}`)
          cy.get('#password').type('admin123')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Password Strength' })
    })
  })

  describe('challenge "loginSupport"', () => {
    it('should be able to log in with original support-team credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`support@${appDomain}`)
          cy.get('#password').type('J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Login Support Team' })
    })
  })

  describe('challenge "loginRapper"', () => {
    it('should be able to log in with original MC SafeSearch credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`mc.safesearch@${appDomain}`)
          cy.get('#password').type('Mr. N00dles')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Login MC SafeSearch' })
    })
  })

  describe('challenge "loginAmy"', () => {
    it('should be able to log in with original Amy credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`amy@${appDomain}`)
          cy.get('#password').type('K1f.....................')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Login Amy' })
    })
  })

  describe('challenge "dlpPasswordSpraying"', () => {
    it('should be able to log in with original Jannik credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`J12934@${appDomain}`)
          cy.get('#password').type('0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Leaked Access Logs' })
    })
  })

  describe('challenge "oauthUserPassword"', () => {
    it('should be able to log in as bjoern.kimminich@gmail.com with base64-encoded email as password', () => {
      cy.get('#email').type('bjoern.kimminich@gmail.com')
      cy.get('#password').type('bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=')
      cy.get('#loginButton').click()

      cy.expectChallengeSolved({ challenge: 'Login Bjoern' })
    })
  })

  describe('challenge "exposedCredentialsChallenge"', () => {
    it('should be able to log in with testing credentials that are leaked on client', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`testing@${appDomain}`)
          cy.get('#password').type('IamUsedForTesting')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Exposed credentials' })
    })
  })
})
