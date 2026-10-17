// CertGuard Pro (Polar) — one place for the checkout URL, product slug, key prefix, price and limits. Pattern:
// UAParse src/lib/pro.js. Keys are validated READ-ONLY against the shared LICENSES KV (written only by the license
// gateway); no Polar HTTP and no Polar token in this Worker. Never log or echo a key.
import { sha256hex } from './limits.js';

/** Polar checkout link (persistent). */
export const PRO_CHECKOUT_URL = 'https://buy.polar.sh/polar_cl_EU23jaHuY4BVGE1EIFLBs9npUZk9p9479tUvN2yrUcy';
/** Polar customer portal (manage / cancel), same org as the other shared Pro products. */
export const PRO_PORTAL_URL = 'https://polar.sh/digital-promo/portal';
export const PRO_PRODUCT_SLUG = 'certguard-pro';
export const PRO_KEY_PREFIX = 'CGPR';
export const PRO_PRICE_USD = 5;

/** Case-insensitive product prefix before the first dash (Polar license-key benefit prefix). */
export function looksLikeProKey(key) {
  if (!key || typeof key !== 'string') return false;
  return (key.trim().split('-')[0] || '').toUpperCase() === PRO_KEY_PREFIX;
}

/** Stable, non-reversible id for a license (limiter + daily quota). Never store or return the raw key. */
export async function proKeyIdFor(rawKey) {
  return 'pro:' + (await sha256hex('certguard-pro:' + rawKey)).slice(0, 32);
}
