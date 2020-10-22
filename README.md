# Cloudflare Worker Validate Cognito JWT

## Introduction

This "library" checks that a JWT created by AWS Cognito is valid for use within
a perticular Cloudflare Workers and Cloudflare KV based environment.

The code is very much based on [AWS examples](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html), making use of:
 - jwk-to-pem
 - jsonwebtoken

The validation checks are:
 - JWT has 3 non-zero length sections
 - Signature is valid against the payload (using public key)
 - Expiry date has not passed already
 - Issuer matches Cognito endpoint URL
 - Audience matches Cognito user pool app client id
 - Token use is "id"

The code makes use of KV to store each PEM encoded JWK by its kid.

The primary method in the library is: 

    export async function validateCognitoJwt(cognitoEndpointUrl, appClientId, 
        kvInstance, cognitoJwt)

Where the parameters are:

    cognitoEndpointUrl - from Cognito config, expected form; 
        https://cognito-idp.<aws-region-x>.amazonaws.com/<aws-region-x>_<idstr>

    appClientId - from Cognito user pool config (an alphanumeric string)

    kvInstance - Cloudflare KV instance used to cache pem values

    cognitoJwt - JWT instance to validate

It is assumed that; cognitoEndpointUrl and appClientId will be configured as 
environment variables in the Workers app wrangler.toml.

It is expected that the library will be included using a statement such as:

    import { validateCognitoJwt } from '@my-liminal-space/cw-validate-cognito-jwt';


## Development

The code lives in [this GitHub repo]().

Testing code that depends upon features of the Cloudflare Worker platform (such
as client HTTP Fetch, which this code uses to fetch the public JWK from the 
Cognito endpoint) is "interesting". In order to build confidence that the 
code will work as expected, the approach taken is to test by deploying the lib 
along with a test harness into a Cloudflare Workers app and point it at a real 
Cognito instance.

The test harness uses the built in 'assert' library to demonstrate that the 
code works as intended.

In the repo, the main library code is in the file 'check-jwt.js' and the test 
harness is in file 'test.js' with package.json 'main' set to 'test.js'. The 
tests can be deployed and run using the bash script 'run-test.sh' (tried on 
Ubuntu 18).

If you want to replicate the test environment, you will need to modify 
wrangler.toml to use your own values.


## Distribution

When packaged for deployment (using pkg.sh), a new folder structure is created 
that is sets up a package focussed on distribtion, which means:
 - only check-jwt.js is included (renamed as index.js)
 - an alternative package.json is included, pointing to index.js

