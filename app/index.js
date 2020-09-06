const Koa = require('koa')
const bodyParser = require('koa-bodyparser');
const Router = require('koa-router')
const axios = require('axios');

const app = new Koa();
app.use(bodyParser());

var router = new Router();

router.get('/hello', async(ctx) => {
    ctx.body = 'hello app'
});

router.get('/login', async(ctx) => {
    ctx.body = '<a href="http://localhost:3002/authorize?response_type=code&client_id=client&state=xyz&redirect_uri=http://localhost:3001/callback&access_token=1">授权</a>'
});

router.get('/callback', async(ctx) => {
    const code = ctx.query.code;
    const res = await axios({
        url: 'http://localhost:3002/token',
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        data: `grant_type=authorization_code&code=${code}&client_id=client&client_secret=secret&redirect_uri=http://localhost:3002/callback`
    });
    const access_token = res.data.access_token
    try {
        const user = await axios.get(`http://localhost:3003/user?access_token=${access_token}`)
        ctx.body = user.data
    } catch (e) {
        ctx.body = { error_description: e.message };
        ctx.status = e.response.status;
    }
});

app.use(router.routes()).use(router.allowedMethods());

app.listen('3001');