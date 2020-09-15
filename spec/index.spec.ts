import { JwtValidator } from "../lib/validator";
import { IJwtValidatorConfig, IValidateTokenResult, IEmailClaim } from "../declarations/declarations";

const fakeToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkNQQnEyOEFFdkl2VkpwdjNad1dUYyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.Tq0NGS79P8COkfcVN8yXRjL-bHdgC40I4P2NIaW9ZrGDCGqDzuaVNGqPFZ9E8QUYhr_5XVMSAyzd5WSpeWjr3t4-c9NUPH-BXzMm89SKaY2lZpfio9-I3HK82sjBojSwDNUOjS_N9XS6wL6itNKR1xZVp5O9iLfbW3BevWh7HLwvzG-VQugVUald8kaHmlN01lLQcGvKIs-D1-5MRINW_1cXyO-XUVdxx1Ar4MURDToeLifhujuY3YHrbug2IB6XkgA67L_-2-0Ixyis-QICiR8Nrtly2f5ReDv7a_mlDBkW0cgrhSHthTZ5lhpbV_HSby654PNFnCONLW7setKyfQ";
const token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkNQQnEyOEFFdkl2VkpwdjNad1dUYyJ9.eyJuaWNrbmFtZSI6Im9zcyIsIm5hbWUiOiJvc3NAbmNoYXQuY29tIiwicGljdHVyZSI6Imh0dHBzOi8vcy5ncmF2YXRhci5jb20vYXZhdGFyL2Y5ZTc4MzUwMTlmMWVjYThlNDYzNTdjNmI5YzljMjIzP3M9NDgwJnI9cGcmZD1odHRwcyUzQSUyRiUyRmNkbi5hdXRoMC5jb20lMkZhdmF0YXJzJTJGb3MucG5nIiwidXBkYXRlZF9hdCI6IjIwMjAtMDktMTJUMTI6MjI6NDIuNDEyWiIsImVtYWlsIjoib3NzQG5jaGF0LmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJpc3MiOiJodHRwczovL25jaGF0LnVzLmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHw1ZjVjOWFkZjFkODBiMTAwNzhlNWRjY2IiLCJhdWQiOiJBcUcwV1ZTWWY3eDMzalhFZDBnM25McmpXY3R2cnY3WSIsImlhdCI6MTU5OTkxNzYxOSwiZXhwIjoxNTk5OTUzNjE5LCJub25jZSI6IjBiTnFuYS5Qb1hqOTBaZGFDZFkzT3lna0VyN2JKZlZHRTV2dW5wXy1fb2gifQ.F0oa69MYLti4doMLDbHRyVW8No4AgcMaM_R58q5QLBg9g7LMlY9cUCNrKhP1R0Bl4T_Y5Wvu9lJ_tSH2s2OGHLCfngCucTJXpjVhX4YCzFR0EH4Wr4ZUQC_iRT5tFEVynENkVfiXmVMWC3swe7EKdLnJfTpKx1jh3qK1XEZpFENEdNtlJT3r8MBAh89AHZ2wncyCKS8t6Gu9jtH3ORmGH6-sxCfrzjalwARC2r_ACWK5dYkKQmlsMwwmIT_yPW0YjGfOXPGcF5rrAG2Ok-Avy9h4jiSdvpjv1yaxSfka8TUPckBbzDNYEfmzN395kYGOlEVK5xW1wCUCG3lYag6k3g";
const payload = {
    nickname: "oss",
    name: "oss@nchat.com",
    picture: "https://s.gravatar.com/avatar/f9e7835019f1eca8e46357c6b9c9c223?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fos.png",
    updated_at: "2020-09-12T12:22:42.412Z",
    email: "oss@nchat.com",
    email_verified: true,
    iss: "https://nchat.us.auth0.com/",
    sub: "auth0|5f5c9adf1d80b10078e5dccb",
    aud: "AqG0WVSYf7x33jXEd0g3nLrjWctvrv7Y",
    iat: 1599917619,
    exp: 1599953619,
    nonce: "0bNqna.PoXj90ZdaCdY3OygkEr7bJfVGE5vunp_-_oh",
};

const getDefaultConfig = (): IJwtValidatorConfig => {
    const config: IJwtValidatorConfig = { issuerUrl: "https://nchat.us.auth0.com/", clientId: "AqG0WVSYf7x33jXEd0g3nLrjWctvrv7Y", tokenUse: "access" };

    return config;
};

const expectError = (result: IValidateTokenResult<IEmailClaim>, errorMessage: string) => {
    expect(result.isValid).toBeFalse();
    expect(result.error).toEqual(new Error(errorMessage));
    expect(result.claim).toBeUndefined();
};

describe("JwtValidator", () => {
    describe("validateToken", () => {
        it("should validate token.", async () => {
            const validator = new JwtValidator(getDefaultConfig(), { validateExp: false, validateIss: true, validateTokenUse: false });

            const result = await validator.validateToken(token);

            expect(result.isValid).toBeTrue();
            expect(result.error).toBeUndefined();
            expect(result.claim).toEqual(payload as any);
        });

        it("should validate iss.", async () => {
            const config = getDefaultConfig();
            config.issuerUrl = "https://nchat.us.auth0.com";
            const validator = new JwtValidator(config, { validateExp: false, validateIss: true, validateTokenUse: false });

            const result = await validator.validateToken<IEmailClaim>(token);

            expectError(result, "claim issuer is invalid");
        });

        it("should validate exp.", async () => {
            const validator = new JwtValidator(getDefaultConfig(), { validateExp: true, validateIss: false, validateTokenUse: false });

            const result = await validator.validateToken<IEmailClaim>(token);

            expectError(result, "jwt expired");
        });

        it("should validate token_use.", async () => {
            const config = getDefaultConfig();
            const accessTokenValidator = new JwtValidator(config, { validateExp: false, validateIss: false, validateTokenUse: true });

            let result = await accessTokenValidator.validateToken<IEmailClaim>(token);

            expectError(result, "claim use is not access");

            config.tokenUse = "id";
            const idTokenValidator = new JwtValidator(config, { validateExp: false, validateIss: false, validateTokenUse: true });

            result = await idTokenValidator.validateToken<IEmailClaim>(token);

            expectError(result, "claim use is not id");
        });

        it("should validate the signature.", async () => {
            const validator = new JwtValidator(getDefaultConfig(), { validateExp: true, validateIss: true, validateTokenUse: true });

            const result = await validator.validateToken<IEmailClaim>(fakeToken);

            expectError(result, "invalid signature");
        });
    });
});
