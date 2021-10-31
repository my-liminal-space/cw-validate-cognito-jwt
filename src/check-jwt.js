var jwkToPem = require('jwk-to-pem');
var jwt = require('jsonwebtoken');


export const JWT_EXPECTED_TOKEN_USE = "id";

/*
  Validate a JWT in the context of this worker environment.
  Returns true if all is well, false if not (or throws an exception if 
  something goes wrong with internal processing calls).

  Parameters:

    cognitoEndpointUrl - from Cognito config, expected form; 
        https://cognito-idp.<aws-region-x>.amazonaws.com/<aws-region-x>_<idstr>

    appClientId - from Cognito user pool config (an alphanumeric string)

    kvInstance - Cloudflare KV instance used to cache pem values

    cognitoJwt - JWT instance to validate


  Checks the:
   - JWT has 3 non-zero length sections
   - Signature is valid against the payload (using public key)
   - Expiry date has not passed already
   - Issuer matches Cognito endpoint URL
   - Audience matches Cognito user pool app client id
   - Token use is id
*/
export async function validateCognitoJwt(cognitoEndpointUrl, appClientId, kvInstance, cognitoJwt) {
  let jwtOk = false;

  let decodedJwt = decodeJwt(cognitoJwt);

  const kid = decodedJwt.header.kid;
  const pem = await findPemByKid(cognitoEndpointUrl, kvInstance, kid);

  if (pem) {
    jwt.verify(cognitoJwt, pem, { algorithms: ['RS256'] }, function(err, decodedToken) {

      if (err) {
        // if an error arose while verifying the token it can't be valid...
      } else {

        /* *** checking token atts (in payload section of jwt) *** */

        // expired 
        if ((typeof decodedJwt.payload.exp) !== "number") {
          return;
        }

        const secondsSinceEpochNow = Math.round((new Date().getTime()) / 1000);
        if (secondsSinceEpochNow >= decodedJwt.payload.exp) {
          return;
        }


        // iss (issuer) - should be COGNITO_ENDPOINT_URL

        if (cognitoEndpointUrl !== decodedJwt.payload.iss) {
          return;
        }


        // aud (audience) - should be COGNITO_APP_CLIENT_ID from user pool

        if (appClientId !== decodedJwt.payload.aud) {
          return;
        }
        

        // token use should be id

        if (JWT_EXPECTED_TOKEN_USE !== decodedJwt.payload.token_use) {
          return;
        }


        // got all the way through, JWT is ok (as far as we can tell)
        jwtOk = true;        

      }

    }); // end jwt.verify
  }

  return jwtOk;
}

/*
  Will return a map with kid as keys and pem encoded key as values (probably 2 keys).
  Throws an exception if something goes wrong with fetch from Cognito endpoint or pem encoding.
*/
export async function fetchCognitoJwk(cognitoEndpointUrl) {

  const cognitoJwtPublicKeyDownloadUrl = cognitoEndpointUrl + "/.well-known/jwks.json";
  //console.log("about to fetch jwk from: " + cognitoJwtPublicKeyDownloadUrl);

  var jwkResult;
  var pems = {};

  const init = {
    headers: {
      'content-type': 'application/json;charset=UTF-8',
    },
  }
  var jwkResponse = await fetch(cognitoJwtPublicKeyDownloadUrl, init);

  jwkResult = await jwkResponse.json();

  var keys = jwkResult['keys'];
  for (var i = 0; i < keys.length; i++) {
    //Convert each key to PEM
    var key_id = keys[i].kid;
    var modulus = keys[i].n;
    var exponent = keys[i].e;
    var key_type = keys[i].kty;
    var jwk = { kty: key_type, n: modulus, e: exponent };
    var pem = jwkToPem(jwk);
    pems[key_id] = pem;
    //console.log("processing jwk entries, added key: " + key_id);
  }

  return pems;
}


/*
  Takes an encoded JWT and returns an object with the token parts split out as:
    - header
    - payload
    - signature
    - raw, the orignal encoded string split on the '.' seperator, an object with properties; 
        header, payload, signature

  Throws an exception if the token doesn't have 3 non-zero length sections.
*/
export function decodeJwt(token) {

  const parts = token.split('.');

  // just make sure that there are 3 parts and all are non zero length...

  if (parts.length != 3) {  // there should be 2 '.' chars, meaning 3 parts
    throw ("Wrong number of sections in JWT, should be 3, got: " + parts.length);
  }

  for (let qq = 0; qq < parts.length; qq++) {
    if (parts[qq].length < 1) {
      throw ("Zero length section in JWT! At position: " + qq);
    }
  }

  const header = JSON.parse(atob(parts[0]));
  const payload = JSON.parse(atob(parts[1]));
  const signature = atob(parts[2].replace(/_/g, '/').replace(/-/g, '+'));
  //console.log(header);
  return {
    header: header,
    payload: payload,
    signature: signature,
    raw: { header: parts[0], payload: parts[1], signature: parts[2] }
  }

}


/*
  Fetch a pem with the given kid
  Returns the corresponding pem if one with the given kid is available from Cognito, null otherwise.
  Throws exceptions if something goes wrong with talking to Cognito or Cloudflare KV

  There are probably smarter ways to store the pem than as json...
*/

const KV_KEY_COGNITO_JWT_PEM = "mls.cognito.jwt.validate.pem.";
const JWK_PEM_POSTFIX_DATA = ".data";
const JWK_PEM_POSTFIX_LOCK = ".lock";

export async function findPemByKid(cognitoEndpointUrl, kvInstance, kId) {
  let jwkPem = null;

  // try reading pem from kv
  const jwkPemDataKey = KV_KEY_COGNITO_JWT_PEM + kId + JWK_PEM_POSTFIX_DATA;
  let jwkPemJson = await kvInstance.get(jwkPemDataKey);

  if (jwkPemJson === null) {

    // pem not found in kv, is there a lock marker?
    const jwkPemLockKey = KV_KEY_COGNITO_JWT_PEM + kId + JWK_PEM_POSTFIX_LOCK;
    let jwkPemLock = await kvInstance.get(jwkPemLockKey);

    if (jwkPemLock === null) {

      // no lock marker yet so assume this is first time in, add lock, go fetch pem (assuming it exists), add to kv 
      // then return
      // (improvement would be to return pem then add to kv)
      // (another improvement would be to add a marker to say that pem does not exist, which would relieve issue of 
      // make up kid)

      const lockData = { lockCreated: Date.now() };
      await kvInstance.put(jwkPemLockKey, JSON.stringify(lockData), {expirationTtl: 62});  // expire lock entry after 62s

      // now go to cognito for public keys
      const pemsMap = await fetchCognitoJwk(cognitoEndpointUrl);
      jwkPem = pemsMap[kId];

      if (jwkPem !== undefined) { // hurray, found a pem - save into kv then return        
        await kvInstance.put(jwkPemDataKey, JSON.stringify(jwkPem), {expirationTtl: 1209600}); // store for 14 days
      } else {
        // interesting, the kId does not map to a Cognito key - cant be a valid JWT (well, not for our purposes), 
        // return null
      }

    } else {

      // there is a lock file, have to wait up to 60s for write to be visible so go get pem direct from Cognito
      // AWS Cognito can manage having a few of our hurd go thundering by... :)

      const pemsMap = await fetchCognitoJwk(cognitoEndpointUrl);
      jwkPem = pemsMap[kId];

    }

  } else {
    jwkPem = JSON.parse(jwkPemJson);
  }

  return jwkPem;
}
