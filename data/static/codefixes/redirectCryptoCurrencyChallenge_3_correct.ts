export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  if (typeof url !== 'string' || !URL.canParse(url)) {
    return false
  }
  const target = new URL(url).href
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || target === new URL(allowedUrl).href
  }
  return allowed
}