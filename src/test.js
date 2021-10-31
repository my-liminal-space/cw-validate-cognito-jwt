import { strict as assert } from 'assert';


import { validateCognitoJwt, fetchCognitoJwk, decodeJwt, findPemByKid } from './check-jwt.js';


/* *** Run tests in a Cloudflare Worker *** */

const QUERY_PARAM_NAME_VALID_JWT = "valid_jwt";


/*
    Workers entry point.
*/
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

    assert.ok(pem, "pem from KV is not truthy");

  }));


  // validate valid JWT

  testList.push(new TestDescription("Check valid JWT verifies with true", async function(){

    const jwtIsValid = await validateCognitoJwt(COGNITO_ENDPOINT_URL, COGNITO_APP_CLIENT_ID
      , MLS_COGNITO, validJwt);

    assert.ok(jwtIsValid, "Not a truthy value from validate valid JWT.");

  }));

  // validate invalid (expired) JWT

  const EXPIRED_JWT = "eyJraWQiOiJxNkdVbnlVQnA1QU9YK0pTd014clViYzZEeUREY2lhbUdEdFJjY2VBZU1ZPSIsImFsZyI6IlJTMjU2In0.eyJhdF9oYXNoIjoiUUJlRC1GWEZCSUlTNWNYWlN1eWdhQSIsInN1YiI6IjYwZjUzMGEzLWIwYjgtNGVmZC1iY2I2LTIyMTNkZTAzMDE3OCIsImF1ZCI6IjVwZWVuNDRyYXRmOGRtNGhwbGp2dGxoZDFtIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTk3MzQ2Njk0LCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV93aFI1RjR4SGsiLCJjb2duaXRvOnVzZXJuYW1lIjoiNjBmNTMwYTMtYjBiOC00ZWZkLWJjYjYtMjIxM2RlMDMwMTc4IiwiZXhwIjoxNTk3MzUwMjk0LCJpYXQiOjE1OTczNDY2OTQsImVtYWlsIjoiYW5keUBmYXIyZ29uZS5jb20ifQ.SV6iHc9-qRLeeqSWiBfCemXxeOhKPmMu8zi9h0n3FCUt2P3QqjdVqz53Wsgjha2p9Z_ptadrV1fps4eTjY4JAmlFG9QkXTpRQax5EBqr_fenikS1RYyliBL4a9eakBNsOxvxjk5C5JlKTQiOolyeGAMoJzNMJ-NkJLptN655DyWQ-ID6q5YIe4OjWEAR5WI0GUlb5PHNp6jcAUxVztlOEnhfz1sb7VGvW8QYEXmJOySS2841vLrkpcFDIUGexdTwxt7s2wBKS6xuBySSn-6elqhMOyNsGXgLEVRj6q1AD2hOX5pkHbc9wN1fdHGexMFSptJK-qe5OhP7-Dki4Bf2UQ";

  testList.push(new TestDescription("Check invalid (expired) JWT verifies with false", async function(){

    const jwtIsValid = await validateCognitoJwt(COGNITO_ENDPOINT_URL, COGNITO_APP_CLIENT_ID
      , MLS_COGNITO, EXPIRED_JWT);

    assert.ok(!jwtIsValid, "A truthy value from validate for invalid JWT.");

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