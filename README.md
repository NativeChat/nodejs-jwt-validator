# nodejs-jwt-validator
NodeJS module which validates the signature and the claims of a JWT.

## Description
This module was created following the documentation of AWS for verification of Cognito tokens:
https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html

and the example code from this repo:
https://github.com/awslabs/aws-support-tools/blob/master/Cognito/decode-verify-jwt/decode-verify-jwt.ts


## Example
```TypeScript
import { JwtValidator } from "nodejs-jwt-validator";
import { IJwtValidatorConfig } from "nodejs-jwt-validator/declarations/declarations";

const clientId = "my-client-id";
const issuerUrl = "https://my-issuer.com/";
const tokenUse = "access";

const config: IJwtValidatorConfig = { issuerUrl, clientId, tokenUse };

const validator = new JwtValidator(config);

const token = "my-jwt";
// Validate the signature of the token and the exp, iss and token_use claims.
const result = await validator.validateToken(token);
console.log(result);
```
