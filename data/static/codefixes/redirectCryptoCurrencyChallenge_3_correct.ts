export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: unknown) => {
  if (typeof url !== 'string' || !URL.canParse(url)) return false
  const target = new URL(url)
  if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password) return false
  for (const allowedUrl of redirectAllowlist) {
    const allowed = new URL(allowedUrl)
    if (target.origin === allowed.origin && target.pathname === allowed.pathname) return true
  }
  return false
}