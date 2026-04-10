/**
 * PATCH: Enhanced Injection Guard with Unicode normalization
 * Addresses GitHub Issue #576 - injection-guard bypass via encoding, homoglyphs
 * 
 * This patch adds Layer 1 mitigation: Input normalization
 * - Converts Unicode homoglyphs to ASCII equivalents (Unicode TR39 confusables)
 * - Decodes ROT13 encoding tricks
 * - Normalizes whitespace and zero-width characters
 */

// Unicode confusables mapping (Cyrillic/Latin lookalikes)
const CONFUSABLE_MAP: Record<string, string> = {
  // Cyrillic → Latin
  'а': 'a',  // CYRILLIC SMALL LETTER A (U+0430)
  'А': 'A',  // CYRILLIC CAPITAL LETTER A (U+0410)
  'е': 'e',  // CYRILLIC SMALL LETTER IE (U+0435)
  'Е': 'E',  // CYRILLIC CAPITAL LETTER IE (U+0415)
  'о': 'o',  // CYRILLIC SMALL LETTER O (U+043E)
  'О': 'O',  // CYRILLIC CAPITAL LETTER O (U+041E)
  'р': 'p',  // CYRILLIC SMALL LETTER ER (U+0440)
  'Р': 'P',  // CYRILLIC CAPITAL LETTER ER (U+0420)
  'с': 'c',  // CYRILLIC SMALL LETTER ES (U+0441)
  'С': 'C',  // CYRILLIC CAPITAL LETTER ES (U+0421)
  'х': 'x',  // CYRILLIC SMALL LETTER HA (U+0445)
  'Х': 'X',  // CYRILLIC CAPITAL LETTER HA (U+0425)
  'і': 'i',  // CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I (U+0456)
  'І': 'I',  // CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I (U+0406)
  'ј': 'j',  // CYRILLIC SMALL LETTER JE (U+0458)
  'Ј': 'J',  // CYRILLIC CAPITAL LETTER JE (U+0408)
  'ѕ': 's',  // CYRILLIC SMALL LETTER DZE (U+0455)
  'Ѕ': 'S',  // CYRILLIC CAPITAL LETTER DZE (U+0405)
  'ґ': 'g',  // CYRILLIC SMALL LETTER GHE WITH UPTURN (U+0491)
  'Ґ': 'G',  // CYRILLIC CAPITAL LETTER GHE WITH UPTURN (U+0490)
  'њ': 'n',  // CYRILLIC SMALL LETTER NJE (U+045A)
  'Њ': 'N',  // CYRILLIC CAPITAL LETTER NJE (U+040A)
  'љ': 'l',  // CYRILLIC SMALL LETTER LJE (U+0459)
  'Љ': 'L',  // CYRILLIC CAPITAL LETTER LJE (U+0409)
  'ћ': 'h',  // CYRILLIC SMALL LETTER TJE (U+045B)
  'Ћ': 'H',  // CYRILLIC CAPITAL LETTER TJE (U+040B)
  'џ': 'd',  // CYRILLIC SMALL LETTER DZHE (U+045F)
  'Џ': 'D',  // CYRILLIC CAPITAL LETTER DZHE (U+040F)
  'ђ': 'dj', // CYRILLIC SMALL LETTER DJE (U+0452)
  'Ђ': 'Dj', // CYRILLIC CAPITAL LETTER DJE (U+0402)
  
  // Zero-width characters
  '\u200B': '',  // ZERO WIDTH SPACE
  '\u200C': '',  // ZERO WIDTH NON-JOINER
  '\u200D': '',  // ZERO WIDTH JOINER
  '\uFEFF': '',  // ZERO WIDTH NO-BREAK SPACE (BOM)
  '\u2060': '',  // WORD JOINER
};

/**
 * Normalize Unicode confusables to ASCII
 * Based on Unicode TR39 Security Profiles
 */
export function normalizeConfusables(input: string): string {
  let normalized = input
  
  // Apply confusables mapping
  for (const [confusable, ascii] of Object.entries(CONFUSABLE_MAP)) {
    normalized = normalized.split(confusable).join(ascii)
  }
  
  // Normalize to NFKC form (compatibility decomposition + canonical composition)
  normalized = normalized.normalize('NFKC')
  
  return normalized
}

/**
 * Remove zero-width and invisible characters that could be used for obfuscation
 */
export function removeInvisibleChars(input: string): string {
  return input
    .replace(/[\u200B-\u200D\uFEFF\u2060\u200E\u200F\u034F\u2028\u2029\u202A-\u202E\u2061-\u2064]/g, '')
    .replace(/\u0000/g, '') // null bytes
    .replace(/[\u2028\u2029]/g, '\n') // line/paragraph separators → newline
}

/**
 * Decode ROT13 encoded text (simple rotation cipher)
 */
export function decodeRot13(input: string): string {
  return input.replace(/[a-zA-Z]/g, (char) => {
    const code = char.charCodeAt(0)
    const base = code >= 97 ? 97 : 65
    return String.fromCharCode(((code - base + 13) % 26) + base)
  })
}

/**
 * Detect if input might be ROT13 encoded
 * Heuristic: high ratio of "suspicious" words that decode to danger terms
 */
export function detectRot13(input: string): boolean {
  const decoded = decodeRot13(input.toLowerCase())
  const dangerTerms = [
    'ignore', 'override', 'execute', 'delete', 'remove', 'rm -rf',
    'bypass', 'disable', 'system', 'admin', 'root', 'sudo'
  ]
  return dangerTerms.some(term => decoded.includes(term))
}

/**
 * Full input normalization for injection scanning
 * Returns normalized string safe for regex matching
 */
export function normalizeForScanning(input: string): string {
  if (!input || typeof input !== 'string') {
    return input
  }
  
  let normalized = input
  
  // Step 1: Remove invisible/zero-width characters
  normalized = removeInvisibleChars(normalized)
  
  // Step 2: Normalize Unicode confusables
  normalized = normalizeConfusables(normalized)
  
  // Step 3: Detect and decode ROT13 if suspicious pattern detected
  // We run the decoded version alongside the original for scanning
  // The original scan still runs, but we also return a decoded version
  
  // Step 4: Normalize excessive whitespace (but preserve single spaces)
  normalized = normalized.replace(/\s{3,}/g, '  ')
  
  return normalized
}

/**
 * Enhanced scan that includes normalized input
 * Returns both original and normalized scan results
 */
export interface EnhancedGuardOptions {
  criticalOnly?: boolean
  maxLength?: number
  context?: 'prompt' | 'display' | 'shell'
  /** Also scan ROT13-decoded version */
  checkRot13?: boolean
}

/**
 * Generate ROT13 variants for scanning
 * Returns array of {label, text} pairs to scan
 */
export function generateDecodingVariants(input: string): Array<{label: string, text: string}> {
  const variants: Array<{label: string, text: string}> = [
    { label: 'original', text: input }
  ]
  
  // Check for ROT13
  if (detectRot13(input)) {
    variants.push({ label: 'rot13-decoded', text: decodeRot13(input) })
  }
  
  // Check for URL encoding
  try {
    const decoded = decodeURIComponent(input)
    if (decoded !== input) {
      variants.push({ label: 'url-decoded', text: decoded })
    }
  } catch {
    // Not valid URL encoding, skip
  }
  
  // Check for mixed/base64 patterns
  const base64Regex = /(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g
  const base64Matches = input.match(base64Regex)
  if (base64Matches) {
    for (const match of base64Matches) {
      if (match.length > 20) { // Only try reasonably sized strings
        try {
          const decoded = atob(match)
          if (decoded !== match && /[\x00-\x1F\x7F-\x9F]/.test(decoded) === false) {
            variants.push({ label: `base64-decoded:${match.slice(0,20)}...`, text: decoded })
          }
        } catch {
          // Not valid base64
        }
      }
    }
  }
  
  return variants
}
