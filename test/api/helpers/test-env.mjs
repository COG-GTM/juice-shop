process.env.NODE_ENV = 'test'

const privilegedTestPasswords = {
  JUICE_SHOP_ADMIN_PASSWORD: 'admin123',
  JUICE_SHOP_BJOERN_GOOGLE_PASSWORD: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=',
  JUICE_SHOP_SUPPORT_PASSWORD: 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P',
  JUICE_SHOP_JANNIK_PASSWORD: '0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB',
  JUICE_SHOP_TIMO_PASSWORD: 'EinBelegtesBrotMitSchinkenSCHINKEN!',
  JUICE_SHOP_BJOERN_PASSWORD: 'monkey summer birthday are all bad passwords but work just fine in a long passphrase',
  JUICE_SHOP_ACCOUNTANT_PASSWORD: 'i am an awesome accountant',
  JUICE_SHOP_LET_US_TEST_PASSWORD: 'IamUsedForTesting'
}
for (const [name, value] of Object.entries(privilegedTestPasswords)) {
  process.env[name] ??= value
}
