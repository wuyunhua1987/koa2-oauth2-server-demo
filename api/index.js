const Koa = require('koa')
const OAuth2 = require('oauth2-server')
const bodyParser = require('koa-bodyparser');
const Router = require('koa-router')
const { Request, Response, UnauthorizedRequestError } = require('oauth2-server')

const app = new Koa();
app.use(bodyParser());

var router = new Router();

const oauth = new OAuth2({
    model: {
        async getAccessToken(accessToken) {
            // throw new UnauthorizedRequestError('token invaild')
            return {
                accessToken: 'dddd',
                accessTokenExpiresAt: new Date(2020, 9, 1, 0, 0, 0),
                scope: '1',
                client: { id: 'client' },
                user: { id: 1 }
            };
        }
    },
    allowBearerTokensInQueryString: true,
    accessTokenLifetime: 4 * 60 * 60
})
app.context.oauth = oauth;

app.use(async(ctx, next) => {
    const request = new Request(ctx.request);
    const response = new Response(ctx.response);
    try {
        ctx.state.oauth = {
            token: await ctx.oauth.authenticate(request, response)
        };
        await next();
    } catch (e) {
        if (e instanceof UnauthorizedRequestError) {
            ctx.status = e.code;
        } else {
            ctx.body = { error: e.name, error_description: e.message };
            ctx.status = e.code;
        }
    }
});

router.get('/hello', async(ctx) => {
    ctx.body = 'hello api'
});

router.get('/user', async(ctx, next) => {
    const { user, client } = ctx.state.oauth.token
    ctx.body = { user, client }
})

app.use(router.routes()).use(router.allowedMethods());

app.listen('3003');