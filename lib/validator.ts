import * as Axios from "axios";
import { verify } from "jsonwebtoken";

// tslint:disable-next-line:no-var-requires
const jwkToPem = require("jwk-to-pem");

import {
    IJwtValidatorConfig,
    IMapOfKidToPublicKey,
    IPublicKeys,
    ITokenHeader,
    IClaim,
    IValidationOptions,
    IValidateTokenResult,
} from "../declarations/declarations";
import { DefaultValidationOptions } from "./constants";

export class JwtValidator {
    private validationOptions: IValidationOptions;
    private cacheKeys?: IMapOfKidToPublicKey;

    constructor(
        private config: IJwtValidatorConfig,
        validationOptions?: IValidationOptions,
    ) {
        this.validationOptions = Object.assign({}, DefaultValidationOptions, validationOptions || {});
    }

    public async validateToken<T>(token: string): Promise<IValidateTokenResult<T>> {
        const result: IValidateTokenResult<T> = { isValid: false };
        try {
            const tokenSections = (token || "").split(".");
            if (tokenSections.length < 2) {
                throw new Error("requested token is invalid");
            }

            const headerJSON = Buffer.from(tokenSections[0], "base64").toString("utf8");
            const header = JSON.parse(headerJSON) as ITokenHeader;
            const keys = await this.getPublicKeys();
            const key = keys[header.kid];
            if (key === undefined) {
                throw new Error("claim made for unknown kid");
            }

            const claim = await this.jwtVerify<T>(token, key.pem);
            const currentSeconds = Math.floor((new Date()).valueOf() / 1000);
            if (this.validationOptions.validateExp && (currentSeconds > claim.exp || currentSeconds < claim.auth_time)) {
                throw new Error("claim is expired or invalid");
            }

            if (this.validationOptions.validateIss && claim.iss !== this.config.issuerUrl) {
                throw new Error("claim issuer is invalid");
            }

            if (this.validationOptions.validateAud && claim.aud !== this.config.clientId) {
                throw new Error("claim aud is invalid");
            }

            if (this.validationOptions.validateTokenUse && claim.token_use !== this.config.tokenUse) {
                throw new Error(`claim use is not ${this.config.tokenUse}`);
            }

            result.isValid = true;
            result.claim = claim;
        } catch (err) {
            result.error = err;
        }

        return result;
    }

    private async getPublicKeys(): Promise<IMapOfKidToPublicKey> {
        if (!this.cacheKeys) {
            const separator = this.config.issuerUrl.endsWith("/") ? "" : "/";
            const url = `${this.config.issuerUrl}${separator}.well-known/jwks.json`;
            const publicKeys = await Axios.default.get<IPublicKeys>(url);
            this.cacheKeys = Object.assign(this.cacheKeys || {}, publicKeys.data.keys.reduce((agg, current) => {
                const pem = jwkToPem(current);
                agg[current.kid] = { instance: current, pem };

                return agg;
            }, {} as IMapOfKidToPublicKey));
        }

        return this.cacheKeys;
    }

    private jwtVerify<T>(token: string, pem: string): Promise<IClaim & T> {
        return new Promise((resolve, reject) => {
            verify(token, pem, { ignoreExpiration: !this.validationOptions.validateExp }, (err, decoded) => {
                if (err) {
                    reject(err);

                    return;
                }

                resolve(decoded as IClaim & T);
            });
        });
    }
}
