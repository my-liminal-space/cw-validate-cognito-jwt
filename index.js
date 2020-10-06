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


/* *** Run tests in a Cloudflare Worker *** */

const QUERY_PARAM_NAME_VALID_JWT = "valid_jwt";


addEventListener('fetch', event => {
  event.respondWith(handleRunTestRequest(event.request));
});

class TestDescription {

  // 2020/10/05, AR - it seems that we can't have public fields ???
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

  //testList.push(new TestDescription("Addition", testAddition));

  testList.push(new TestDescription("Fetch PEMs map", testFetchCognitoJwk));

  const validJwt = getRequestQueryParameterByName(request, QUERY_PARAM_NAME_VALID_JWT);
  testList.push(new TestDescription("Decode valid JWT", function(){
    let decodedJwt = decodeJwt(validJwt);
    assert(decodedJwt, "Should be a valid JWT format");
  }));

  // chop final part off (but leave the last .)

  const invalidJwtTwoSeperatorsZeroLenghtLastPart = validJwt.substring(0, validJwt.lastIndexOf("."));
  testList.push(new TestDescription("Decode JWT with two seperators but no last section", function(){

    let decodedJwt;

    try {
      decodedJwt = decodeJwt(invalidJwtTwoSeperatorsZeroLenghtLastPart);
      assert.fail("A JWT with zero length final part should not decode successfully");
    } catch (err) {
      console.info("Decode JWT with two seperators but no last section, exception: " + err);
      assert.strictEqual("Wrong number of sections in JWT, should be 3, got: 2", err);
    }

  }));

  // chop trailing dot off (so there is only one seperator in the string)

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

  return new Response(JSON.stringify(testList), {
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