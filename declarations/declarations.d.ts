export interface IJwtValidatorConfig {
    issuerUrl: string;
    clientId: string;
    tokenUse?: string;
}

export interface IClaim {
    auth_time: number;
    iss: string;
    exp: number;
    username: string;
    client_id: string;
    token_use?: string;
}

export interface IEmailClaim {
    email: string;
    email_verified: boolean;
}

export interface IValidationOptions {
    validateExp: boolean;
    validateIss: boolean;
    validateTokenUse: boolean;
}

export interface IValidateTokenResult<T> {
    isValid: boolean;
    claim?: IClaim & T;
    error?: Error;
}

interface ITokenHeader {
    kid: string;
    alg: string;
}

interface IPublicKey {
    alg: string;
    e: string;
    kid: string;
    kty: string;
    n: string;
    use: string;
}

interface IPublicKeyMeta {
    instance: IPublicKey;
    pem: string;
}

interface IPublicKeys {
    keys: IPublicKey[];
}

interface IMapOfKidToPublicKey {
    [key: string]: IPublicKeyMeta;
}
