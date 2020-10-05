import { strict as assert } from 'assert';


var jwkToPem = require('jwk-to-pem');


export async function fetchCognitoJwk(cognitoEndpointUrl) {

  const cognitoJwtPublicKeyDownloadUrl = cognitoEndpointUrl + "/.well-known/jwks.json";
  console.log("about to fetch jwk from: " + cognitoJwtPublicKeyDownloadUrl);

  var jwkResult;
  var pems = {};

  try {

      const init = {
          headers: {
              'content-type': 'application/json;charset=UTF-8',
          },
      }
      var jwkResponse = await fetch(cognitoJwtPublicKeyDownloadUrl, init);
      console.log("got jwkResponse");

      jwkResult = await jwkResponse.json();

      console.log("got jwkResult: " + jwkResult);


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

  } catch (err) {
      console.log("problem downloading jwk: " + err);
  }

  console.log("jwk is:\n" + JSON.stringify(jwkResult));

  return pems;
}


/* *** Run tests in a Cloudflare Worker *** */

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