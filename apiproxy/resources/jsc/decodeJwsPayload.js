// Decode the middle (payload) segment of a JWS.
// A JWS looks like: header.payload.signature
// Each segment is Base64URL encoded (uses - and _ , and has no = padding),
// so we must convert to standard Base64 before decoding.

function base64UrlDecode(input) {
  // 1. Convert Base64URL alphabet to standard Base64 alphabet.
  var b64 = input.replace(/-/g, '+').replace(/_/g, '/');

  // 2. Re-add the padding that Base64URL strips off.
  var pad = b64.length % 4;
  if (pad === 2) {
    b64 += '==';
  } else if (pad === 3) {
    b64 += '=';
  } else if (pad === 1) {
    // Length 1 mod 4 is never valid Base64 - bail out.
    throw new Error('Invalid Base64URL string length');
  }

  // 3. Decode. In the Apigee/Rhino JS engine, decodeBase64 is not available,
  //    so we use the Java Base64 decoder exposed through the sandbox when
  //    present; otherwise fall back to a manual decoder.
  var bytes;
  if (typeof decodeBase64 === 'function') {
    return decodeBase64(b64);
  }
  // Manual Base64 -> UTF-8 string decode (pure JS, no external deps).
  return manualBase64Decode(b64);
}

function manualBase64Decode(str) {
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
  var output = '';
  str = str.replace(/[^A-Za-z0-9+/=]/g, '');

  var bytes = [];
  var i = 0;
  while (i < str.length) {
    var enc1 = chars.indexOf(str.charAt(i++));
    var enc2 = chars.indexOf(str.charAt(i++));
    var enc3 = chars.indexOf(str.charAt(i++));
    var enc4 = chars.indexOf(str.charAt(i++));

    var chr1 = (enc1 << 2) | (enc2 >> 4);
    var chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
    var chr3 = ((enc3 & 3) << 6) | enc4;

    bytes.push(chr1);
    if (enc3 !== 64) { bytes.push(chr2); }
    if (enc4 !== 64) { bytes.push(chr3); }
  }

  // Interpret the resulting bytes as UTF-8.
  return utf8BytesToString(bytes);
}

function utf8BytesToString(bytes) {
  var result = '';
  var i = 0;
  while (i < bytes.length) {
    var b1 = bytes[i++];
    if (b1 < 0x80) {
      result += String.fromCharCode(b1);
    } else if (b1 >= 0xC0 && b1 < 0xE0) {
      var b2 = bytes[i++];
      result += String.fromCharCode(((b1 & 0x1F) << 6) | (b2 & 0x3F));
    } else if (b1 >= 0xE0 && b1 < 0xF0) {
      var b2 = bytes[i++];
      var b3 = bytes[i++];
      result += String.fromCharCode(((b1 & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F));
    } else {
      // 4-byte sequence (outside BMP) - build a surrogate pair.
      var b2 = bytes[i++];
      var b3 = bytes[i++];
      var b4 = bytes[i++];
      var cp = ((b1 & 0x07) << 18) | ((b2 & 0x3F) << 12) | ((b3 & 0x3F) << 6) | (b4 & 0x3F);
      cp -= 0x10000;
      result += String.fromCharCode(0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
    }
  }
  return result;
}

// --- Main ---
// NOTE: For now the middle (payload) segment is passed in directly as `jws`,
// so we decode it as-is. No header.payload.signature splitting is done here.
var payloadSegment = context.getVariable('jws');

if (payloadSegment === null || payloadSegment === undefined || ('' + payloadSegment).length === 0) {
  context.setVariable('jws.error', 'jws variable is empty or unresolved');
} else {
  payloadSegment = '' + payloadSegment;
  try {
    var decodedPayload = base64UrlDecode(payloadSegment);
    context.setVariable('jws.payload.decoded', decodedPayload);
  } catch (e) {
    context.setVariable('jws.error', 'failed to decode payload: ' + e.message);
  }
}
