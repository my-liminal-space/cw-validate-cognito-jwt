import { strict as assert } from 'assert';


var jwkToPem = require('jwk-to-pem');


/*
  Will return a map with kid as keys and pem encoded key as values (probably 2 keys).
  Throws an exception if something goes wrong with fetch from Cognito endpoint or pem encoding.
*/
export async function fetchCognitoJwk(cognitoEndpointUrl) {

  const cognitoJwtPublicKeyDownloadUrl = cognitoEndpointUrl + "/.well-known/jwks.json";
  console.log("about to fetch jwk from: " + cognitoJwtPublicKeyDownloadUrl);

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
    console.log("processing jwk entries, added key: " + key_id);
  }

  return pems;
}


/*
  Takes an encoded JWT and returns an object with the token parts split out as:
    - header
    - payload
    - signature
    - raw, the orignal encoded string split on the '.' seperator, an object with properties; header, payload, signature

  Throws an exception if the token doesn't have 3 non-zero length sections.
*/
function decodeJwt(token) {

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
  console.log(header);
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

      // no lock marker yet so assume this is first time in, add lock, go fetch pem (assuming it exists), add to kv then return
      // (improvement would be to return pem then add to kv)
      // (another improvement would be to add a marker to say that pem does not exist, which would releive issue of make up kid)

      const lockData = { lockCreated: Date.now() };
      await kvInstance.put(jwkPemLockKey, JSON.stringify(lockData), {expirationTtl: 62});  // auto expire the lock entry after 62 seconds

      // now go to cognito for public keys
      const pemsMap = await fetchCognitoJwk(cognitoEndpointUrl);
      jwkPem = pemsMap[kId];

      if (jwkPem !== undefined) { // hurray, found a pem - save into kv then return        
        await kvInstance.put(jwkPemDataKey, JSON.stringify(jwkPem), {expirationTtl: 1209600}); // store for 14 days
      } else {
        // interesting, the kId does not map to a Cognito key - cant be a valid JWT (well, not for our purposes), return null
      }

    } else {

      // there is a lock file, have to wait up to 60s for write to be visible so go get pem direct from Cognito

      const pemsMap = await fetchCognitoJwk(cognitoEndpointUrl);
      jwkPem = pemsMap[kId];

    }

  } else {
    jwkPem = JSON.parse(jwkPemJson);
  }

  return jwkPem;
}



/* *** Run tests in a Cloudflare Worker *** */

const QUERY_PARAM_NAME_VALID_JWT = "valid_jwt";


addEventListener('fetch', event => {
  event.respondWith(handleRunTestRequest(event.request));
});

class TestDescription {

  // 2020/10/05, AR - it seems that we can't have class public fields ???
  //testName;
  //testFunc;
  //testPassed;
  //msg;

  constructor(testName, testFunc) {
    this.testName = testName;
    this.testFunc = testFunc;
  }

}

async function handleRunTestRequest(request) {

  let testList = [];


  // Fetch jwk and convert to pem

  testList.push(new TestDescription("Fetch PEMs map", testFetchCognitoJwk));


  // Decode valid JWT
  const validJwt = getRequestQueryParameterByName(request, QUERY_PARAM_NAME_VALID_JWT);
  testList.push(new TestDescription("Decode valid JWT", function(){
    let decodedJwt = decodeJwt(validJwt);
    assert(decodedJwt, "Should be a valid JWT format");
  }));


  // Decode JWT chop final part off (but leave the last .)
  const invalidJwtTwoSeperatorsZeroLenghtLastPart = validJwt.substring(0, validJwt.lastIndexOf("."));
  testList.push(new TestDescription("Decode JWT with two seperators but no last section", async function(){

    let decodedJwt;

    try {
      decodedJwt = decodeJwt(invalidJwtTwoSeperatorsZeroLenghtLastPart);
      assert.fail("A JWT with zero length final part should not decode successfully");
    } catch (err) {
      console.info("Decode JWT with two seperators but no last section, exception: " + err);
      assert.strictEqual("Wrong number of sections in JWT, should be 3, got: 2", err);
    }

  }));

  // Decode JWT chop trailing dot off (so there is only one seperator in the string)

  const invalidJwtOnlyOneSeperator = invalidJwtTwoSeperatorsZeroLenghtLastPart.substring(0
    , invalidJwtTwoSeperatorsZeroLenghtLastPart.length - 1);
  testList.push(new TestDescription("Decode JWT only one seperator", function(){

    let decodedJwt;

    try {
      decodedJwt = decodeJwt(invalidJwtOnlyOneSeperator);
      assert.fail("only one seperator should not decode");
    } catch (err) {
      console.info("Decode JWT only one seperator, exception: " + err);
      assert.strictEqual("Wrong number of sections in JWT, should be 3, got: 2", err);
    }
    
  }));


  // using Cloudflare KV to store pem encoded jwt

  testList.push(new TestDescription("Find pem encoded jwk for valid kid", async function(){

    const decodedJwt = decodeJwt(validJwt);
    const kId = decodedJwt.header.kid;
    console.info("kid is: " + kId);

    const pem = await findPemByKid(COGNITO_ENDPOINT_URL, MLS_COGNITO, kId);
    console.info("pem is: " + pem);

  }));


  // run tests

  let allTestsPassed = true;

  for (let yy = 0; yy < testList.length; yy++) {

    let currentTest = testList[yy];

    try {
      await currentTest.testFunc();
      currentTest.testPassed = true;
      console.info("Test passed: " + currentTest.testName);
    } catch (err) {
      allTestsPassed = false;
      currentTest.testPassed = false;
      currentTest.msg = err;
      console.warn("Test failed: " + currentTest.testName + ", msg: " + err);
    }

  }

  // report results

  return new Response(JSON.stringify(testList, null, 2), {
    headers: { 'content-type': 'text/plain' },
    "status": allTestsPassed? 200 : 500,
  });

}

async function testFetchCognitoJwk() {
  let pemMap = await fetchCognitoJwk(COGNITO_ENDPOINT_URL);
  assert(pemMap, "map of pems from jwk is null");
  assert(Object.keys(pemMap).length > 0, "no keys in pems map");
}


// from https://community.cloudflare.com/t/parse-url-query-strings-with-cloudflare-workers/90286
function getRequestQueryParameterByName(request, name) {

  const url = request.url;

  name = name.replace(/[\[\]]/g, '\\$&');
  name = name.replace(/\//g, '');
  var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
    results = regex.exec(url);

  if (!results) return null
  else if (!results[2]) return ''
  else if (results[2]) {
    results[2] = results[2].replace(/\//g, '')
  }

  return decodeURIComponent(results[2].replace(/\+/g, ' '));
}