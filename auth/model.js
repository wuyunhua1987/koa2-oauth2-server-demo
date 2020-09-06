module.exports = {
    async getClient(clientId, clientSecret) {
        return {
            id: 'client',
            redirectUris: ['http://localhost:3001/callback'],
            grants: ['authorization_code']
        };
    },
    async saveAuthorizationCode(code, client, user) {
        return {
            authorizationCode: code.authorizationCode,
            expiresAt: code.expiresAt,
            redirectUri: code.redirectUri,
            scope: code.scope,
            client: { id: client.id },
            user: { id: user.id }
        };
    },
    async getAccessToken(accessToken) {
        return {
            accessToken: 'dddd',
            accessTokenExpiresAt: new Date(2020, 9, 1, 0, 0, 0),
            scope: '1',
            client: { id: 'client' },
            user: { id: 1 }
        };
    },
    async getAuthorizationCode(code) {
        return {
            code: code,
            expiresAt: new Date(2020, 9, 1, 0, 0, 0),
            redirectUri: 'http://localhost:3002/callback',
            scope: '1',
            client: { id: 'client' },
            user: { id: 1 }
        };
    },
    async revokeAuthorizationCode(code) {
        return true
    },
    async saveToken(token, client, user) {
        return {
            accessToken: token.accessToken,
            accessTokenExpiresAt: token.accessTokenExpiresAt,
            refreshToken: token.accessToken,
            refreshTokenExpiresAt: token.refreshTokenExpiresAt,
            scope: token.scope,
            client: client,
            user: user
        };
    },
}