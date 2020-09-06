const Koa = require('koa')
const OAuth2 = require('oauth2-server')
const bodyParser = require('koa-bodyparser');
const Router = require('koa-router')
const { Request, Response, UnauthorizedRequestError } = require('oauth2-server')

const app = new Koa();
app.use(bodyParser());

var router = new Router();

router.get('/hello', async(ctx) => {
    ctx.body = 'hello auth'
});

const oauth = new OAuth2({
    model: require('./model'),
    allowBearerTokensInQueryString: true,
    accessTokenLifetime: 4 * 60 * 60
})
app.context.oauth = oauth;

router.get('/authorize', async(ctx, next) => {
    const request = new Request(ctx.request);
    const response = new Response(ctx.response);

    try {
        ctx.state.oauth = {
            code: await ctx.oauth.authorize(request, response)
        };

        ctx.body = response.body;
        ctx.status = response.status;

        ctx.set(response.headers);
    } catch (e) {
        if (e instanceof UnauthorizedRequestError) {
            ctx.status = e.code;
        } else {
            ctx.body = { error: e.name, error_description: e.message };
            ctx.status = e.code;
        }

        return ctx.app.emit('error', e, ctx);
    }
})

router.post('/token', async(ctx) => {
    const request = new Request(ctx.request);
    const response = new Response(ctx.response);
    try {
        ctx.state.oauth = {
            token: await ctx.oauth.token(request, response)
        };

        ctx.body = response.body;
        ctx.status = response.status;

        ctx.set(response.headers);
    } catch (e) {
        if (e instanceof UnauthorizedRequestError) {
            ctx.status = e.code;
        } else {
            ctx.body = { error: e.name, error_description: e.message };
            ctx.status = e.code;
        }

        return ctx.app.emit('error', e, ctx);
    }
})

app.use(router.routes()).use(router.allowedMethods());

app.listen('3002');