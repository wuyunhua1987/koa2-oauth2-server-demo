本文是一篇新手教程，目的是提供一个有效的指引，让初次接触OAuth2的同学快速掌握关键信息，快速实现功能，本文不会涉及原理、源码

---

## 什么是OAuth2

关于OAuth2的解释，网络上相关文章100%会写，有详细的，有简短的，但是很多新手不明白什么是协议，协议意味着什么？

OAuth2协议强制要求你怎么做，你不能有自己的想法。请求必须是xxx，返回必须是xxx，步骤必须是xxx。因为都被强制了，张三的实现和李四的实现，接口必然完全一样。node的实现和php的实现，接口必然完全一样。

要想掌握OAuth2，必须看完这份协议[RFC6749](https://tools.ietf.org/html/rfc6749)，这里有一份中文版的[RFC6749](https://github.com/jeansfish/RFC6749.zh-cn)

## oauth2-server包

[oauth2-server](https://github.com/oauthjs/node-oauth2-server)是OAuth2协议nodejs的实现

他是OAuth2协议的完整实现，他提供了3个接口供我们使用，同时他要求我们必须告诉他token是怎么存储的。[文档](https://oauth2-server.readthedocs.io/en/latest/index.html)里详细描述

他用来辅助你实现授权和认证的具体功能，你可以在任何nodejs框架中使用，也可以选择任意的后端存储

他不是用来做注册登录的，也不是用来替代`jwt`的

## 使用Koa和oauth2-server实现授权码流程

我们完全按照RFC6749规定的流程来做。

     +--------+                               +---------------+
     |        |--(A)- Authorization Request ->|   Resource    |
     |        |                               |     Owner     |
     |        |<-(B)-- Authorization Grant ---|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(C)-- Authorization Grant -->| Authorization |
     | Client |                               |     Server    |
     |        |<-(D)----- Access Token -------|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(E)----- Access Token ------>|    Resource   |
     |        |                               |     Server    |
     |        |<-(F)--- Protected Resource ---|               |
     +--------+                               +---------------+

                    Figure 1: Abstract Protocol Flow

- A是第三方应用询问`Resource Owner`是否授权，举个例子，第三方app选择微信登录的时候，跳转到微信，询问是否授权登录
- B是`Resource Owner`同意授权，回调第三方应用，同时附上`code`
- C是第三方应用收到回调后，带着`code`，去找`Authorization Server`，换取`token`
- D是`Authorization Server`验证`code`通过后，返回第三方应用一个`token`
- E是第三方应用拿着`token`去`Resource Server`请求资源，举个例子，微信API里获取用户头像昵称，API要求token验证
- F是`Resource Server`验证`token`通过后，返回给第三方应用程序资源，比如头像昵称

### 一、搭建三个http服务器，分别作为第三方应用、授权服务器、资源服务器

```bash
mkdir koa2-oauth2-server & cd koa2-oauth2-server
yarn init
yarn add koa koa-router koa-bodyparser oauth2-server jsonwebtoken
```

编辑package.json，加上入口scripts

```
// ...
"scripts": {
  "auth": "node ./auth",
  "app":  "node ./app",
  "api": "node ./api"
}
```

```javascript
// app/index.js the third app http server 3001
const Koa = require('koa')
const bodyParser = require('koa-bodyparser');
const Router = require('koa-router')

const app = new Koa();
app.use(bodyParser());

var router = new Router();

router.get('/hello', async(ctx) => {
    ctx.body = 'hello app'
});

app.use(router.routes()).use(router.allowedMethods());

app.listen('3001');
```

```javascript
// auth/index.js the authorize http server 3002
const Koa = require('koa')
const OAuth2 = require('oauth2-server')
const bodyParser = require('koa-bodyparser');
const Router = require('koa-router')

const app = new Koa();
app.use(bodyParser());

var router = new Router();

router.get('/hello', async(ctx) => {
    ctx.body = 'hello auth'
});

app.use(router.routes()).use(router.allowedMethods());

app.listen('3002');
```

```javascript
// api/index.js the resource http server 3003
const Koa = require('koa')
const bodyParser = require('koa-bodyparser');
const Router = require('koa-router')

const app = new Koa();
app.use(bodyParser());

var router = new Router();

router.get('/hello', async(ctx) => {
    ctx.body = 'hello api'
});

app.use(router.routes()).use(router.allowedMethods());

app.listen('3003');
```
---

### 二、第三方app应用请求授权（步骤A）

根据RFC6749协议中的规定，第三方请求授权必须满足以下条件

请求授权服务器授权uri的规定，需要提供以下参数

- response_type 必需 我们这里是`code`
- client_id 必需 客户端标识
- redirect_uri 可选的 成功后重定向`uri`
- scope 可选的 申请范围
- state 必需 客户端用于维护请求和回调之间状态的值

如果`resource owner`允许授权，要求返回302重定向，重定向到`redirect_uri`，并带上以下数据:

- code 必需 授权服务器生成的授权码
- state 必需 请求中携带的状态值

如果`resource owner`不允许访问，或者出现其他错误，要求返回302重定向，并重定向到`redirect_uri`，并带上以下数据:

- error 必需
  - invalid_request 请求缺少必需的参数、包含无效的参数值、包含一个参数超过一次或其他不良格式
  - unauthorized_client 客户端未被授权使用此方法请求授权码
  - access_denied 资源所有者或授权服务器拒绝该请求
  - unsupported_response_type 授权服务器不支持使用此方法获得授权码
  - invalid_scope 请求的范围无效，未知的或格式不正确
  - server_error 授权服务器遇到意外情况导致其无法执行该请求
  - temporarily_unavailable 授权服务器由于暂时超载或服务器维护目前无法处理请求
- error_description 可选 提供额外信息的人类可读的信息
- error_uri 可选 指向带有有关错误的信息的人类可读网页的URI
- state 必需 请求中携带的状态值

一个请求授权例子：

```
GET http://localhost:3002/authorize?response_type=code&client_id=client&state=xyz&redirect_uri=http://localhost:3001/callback HTTP/1.1
Content-Type: application/x-www-form-urlencoded
```

接下来我们来写代码实现协议，修改`auth/index.js`。`oauth2-server`包提供了3个方法给我们使用，这里会用到`oauth.authorize()`，他的文档在[这里](https://oauth2-server.readthedocs.io/en/latest/api/oauth2-server.html#authenticate-request-response-options-callback)

```javascript
// 省略...
const { Request, Response, UnauthorizedRequestError } = require('oauth2-server')
// 省略...
const oauth = new OAuth2({
    model: require('./model')
})
app.context.oauth = oauth;

router.get('/authorize', async(ctx, next) => {
    // 构造oauth2-server的request、response
    const request = new Request(ctx.request);
    const response = new Response(ctx.response);

    try {
        // 调用oauth2-server的authorize生成code
        ctx.state.oauth = {
            code: await ctx.oauth.authorize(request, response)
        };
        // 使用oauth2-server的response
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
// 省略...
```

`oauth2-server`要求我们提供存储的具体实现，我们写一个`model.js`，先什么都不写

```javascript
// auth/model.js oauth2-server的存储实现
module.exports = {
    // 先什么都不写，看看会发生什么
}
```

运行以下`yarn run auth`

接下来我们编写app部分的代码，先编写一个按钮用于发起授权请求，再编写一个callback用于授权回调

```javascript
// app/index.js
// 省略...
router.get('/login', async(ctx) => {
    // uri必需这么写,client_id先随便写一个，redirect_uri写callback
    ctx.body = '<a href="http://localhost:3002/authorize?response_type=code&client_id=client&state=xyz&redirect_uri=http://localhost:3001/callback">授权</a>'
});

router.get('/callback', async(ctx) => {
    // 输出code
    ctx.body = ctx.query.code
});
// 省略...
```

运行app`yarn run app`，打开浏览器，输入`http://localhost:3001/login`，点击`授权`链接，观察页面。不出意外将会看到这样的结果：

```
{
    error: "invalid_argument",
    error_description: "Invalid argument: model does not implement `getClient()`"
}
```

> 注意：这里的错误是授权服务器发出的，并不是授权回调后展示的错误

这个错误提示很明显了，auth2-server要求的model，必需要实现`getClient()`方法，我们先查看文档看看这个方法是干啥的，他的文档在[这里](https://oauth2-server.readthedocs.io/en/latest/model/spec.html#model-getclient)

这个方法要求实现如何根据client_id/client_secret得到client object，具体一点就是根据clientId、clientSecret去存储里找到到client对象，参数和返回文档已经给了，我们来实现一下，这里使用内存存储实现

```javascript
// auth/model.js 实现getClient
module.exports = {
    async getClient(clientId, clientSecret) {
        return {
            id: 'client',
            redirectUris: ['http://localhost:3001/callback'],
            grants: ['authorization_code']
        };
    }
}
```

> 为了演示，直接写死了，真实业务中，是会先注册clientId/clientSecret到数据库里，这里检索出来即可

重新运行auth服务`yarn run auth`，再操作一次点击`授权`，观察页面。不出意外会看到这样的结果：

```
{
    error: "invalid_argument",
    error_description: "Invalid argument: model does not implement `saveAuthorizationCode()`"
}
```

有了之前的经验，很明显这里需要我们实现`saveAuthorizationCode()`，阅读`oauth2-server`文档，我们实现一下：

```javascript
// auth/model.js 实现saveAuthorizationCode()
async saveAuthorizationCode(code, client, user) {
    return {
        authorizationCode: code.authorizationCode,
        expiresAt: code.expiresAt,
        redirectUri: code.redirectUri,
        scope: code.scope,
        client: { id: client.id },
        user: { id: user.id }
    };
}
```

> 为了演示，直接写死了，真实业务中，需要把这些数据保存到数据库中，否则后续无法判断是否已使用，无法判断是否已失效

重新运行`yarn run auth`，重复上一步操作，观察页面，提示缺少`getAccessToken()`的实现，根据文档实现一下：

```javascript
// auth/model.js 实现getAccessToken()
async getAccessToken(accessToken) {
    return {
        accessToken: 'dddd',
        accessTokenExpiresAt: new Date(2020, 09, 01, 10, 10, 10),
        scope: '1',
        client: { id: 'client' },
        user: { id: 1 }
    };
}
```

> 为了演示，直接写死了，真实业务中，需要根据accessToken去数据库里查寻token对象

重新运行`yarn run auth`，重复上一步操作，观察页面，这次不再提示缺少xxx方法的实现了，而是提示`Unauthorized`，并且返回的http状态码是401，说明未登录，怎么回事呢？

因为没有登录授权服务器，授权服务器并不知道`resource owner`是谁，就无法询问。真实业务中，这里发现401，就需要弹出登录界面，先让用户完成登录。之后再询问用户是否授权，选择授权范围，再带上`access_token`重新请求授权

我们先绕过这一步，后面再完善，在请求URL后面加上`access_token=1`，使得请求合规，后续的验证身份环节，需要在`auth/model.js`的`getAccessToken()`方法中验证身份，但我们不处理，这样不论access_token是什么总是能通过身份认证

```javascript
// app/index.js 
// 省略...
router.get('/login', async(ctx) => {
    ctx.body = '<a href="http://localhost:3002/authorize?response_type=code&client_id=client&state=xyz&redirect_uri=http://localhost:3001/callback&access_token=1">授权</a>'
})
// 省略...
```

为了允许`uri query`携带`access_token`参数，我们需要修改一下auth/index.js代码

```javascript
// auth/index.js allow token in query string
// 省略...
const oauth = new OAuth2({
    model: require('./model'),
    allowBearerTokensInQueryString: true,
    accessTokenLifetime: 4 * 60 * 60
})
// 省略...
```

重新运行`yarn run auth` & `yarn run app`，重复上一步操作，观察页面。不出意外会看到重定向，`http://localhost:3001/callback?code=ae4354425c3a3bb75ef5e969a19ebd304a0736ef&state=xyz`

步骤B成功了，拿到了`code`，下一步，我们用`code`换取通行证`token`

---

### 三、第三方app应用换取token（步骤C）

上一步我们在`/callback`里拿到了`code`，接下来要用`code`去授权服务器换取`token`，根据RFC6749协议中的规定，第三方请求获取token必须满足以下条件

请求授权服务器获取token uri的规定，需要提供以下参数

- grant_type 必需 这里必须设置为`authorization_code`
- code 必需 从授权服务器拿到的`code`
- redirect_uri 必需 上一步中`redirect_uri`，必须完全一样
- client_id 必需 客户端id
- client_secret 必需 客户端secret

请求类型必须是`post`，`content-type`必须是`application/x-www-form-urlencoded`，例如

```
POST http://localhost:3002/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer 1

grant_type=authorization_code&code=2d6d7da2ed7c405ade522ced89a875bc2b65c8e1&client_id=client&client_secret=secret&redirect_uri=http://localhost:3002/callback
```

> 注意：一般情况下，这一步请求需要在服务器里完成，避免在客户端完成，因为涉及client_secret，避免泄露

请求成功的返回必须是这样子的

```
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache
{
  "access_token":"2YotnFZFEjr1zCsicMWpAA",
  "token_type":"example",
  "expires_in":3600,
  "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
  "example_parameter":"example_value"
}
```

我们编写一个`/token`的uri来实现换取token功能

```javascript
// auth/index.js 
// 省略...
router.post('/token', async(ctx) => {
    const request = new Request(ctx.request);
    const response = new Response(ctx.response);
    try {
        // 调用oauth2-server的token()生成token
        ctx.state.oauth = {
            token: await ctx.oauth.token(request, response)
        };

        // 使用oauth2-server的response
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
// 省略...
```

接下来我们在app里请求授权服务器换取token

```javascript
// app/index.js
const axios = require('axios');
// 省略...
router.get('/callback', async(ctx) => {
    const code = ctx.query.code;
    const res = await axios({
        url: 'http://localhost:3002/token',
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        data: `grant_type=authorization_code&code=${code}&client_id=client&client_secret=secret&redirect_uri=http://localhost:3002/callback`
    });
    console.log(res.data);
    ctx.body = "ok"
});
// 省略...
```

> `axios`是node中httpclient库，记得`yarn add axios`

现在重启一下，`yarn run auth` & `yarn run app`，重复上一步中的授权，页面显示Internal Server Error，看一下终端给出的异常信息：invalid_argument: Invalid argument: model does not implement getAuthorizationCode()

很明显，需要继续实现model.js里的方法，参考文档，补充方法，重复上述步骤，依次实现`revokeAuthorizationCode()`、`saveToken()`

```javascript
// auth/model.js
// 省略...
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
// 省略...
```

重新运行`yarn run auth`，不出意外会看到200 ok，观察终端，会发现授权服务器返回了token给我们：

```
{
    access_token: "e1062fc1a93d9b86231090a7ca2b221dd0eb7d8a",
    token_type: "Bearer",
    expires_in: 14399,
    refresh_token: "e1062fc1a93d9b86231090a7ca2b221dd0eb7d8a",
    scope: "1"
}
```

步骤D成功了，拿到了`token`，下一步，我们用`token`获取资源

---

### 四、从API服务器获取数据（步骤E）

上一步我们拿到了通行证token，我们试一下从API服务器获取用户数据，资源都是受保护的，我们写一个中间件用来做用户身份验证，验证方法使用`oauth2-server`提供的`authenticate`方法，这个方法要求必须实现`getAccessToken()`方法，我们在这个方法里面决定他是否通过身份验证，如果通过返回固定格式，如果没通过，抛出`UnauthorizedRequestError`异常，具体实现如下：

```javascript
// api/index.js
const OAuth2 = require('oauth2-server')
const { Request, Response, UnauthorizedRequestError } = require('oauth2-server')
const oauth = new OAuth2({
    model: {
        async getAccessToken(accessToken) {
            // 省略验证过程，如果没通过，取消下面这行的注释
            //throw new UnauthorizedRequestError('token invaild')
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

// 获取资源，如果如果通过了中间件的身份验证，这里就能拿到userid
router.get('/user', async(ctx, next) => {
    const { user, client } = ctx.state.oauth.token
    ctx.body = { user, client }
});
```

> 为了演示，没有写具体如何验证的，真实业务中可以使用数据库验证，也可以使用jwt验证

加下来就可以在app中请求API了，改一下`callback`方法

```javascript
// app/index.js
router.get('/callback', async(ctx) => {
    const code = ctx.query.code;
    const res = await axios({
        url: 'http://localhost:3002/token',
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        data: `grant_type=authorization_code&code=${code}&client_id=client&client_secret=secret&redirect_uri=http://localhost:3002/callback`
    });
    // 带上token去请求资源
    const access_token = res.data.access_token
    try {
        const user = await axios.get(`http://localhost:3003/user?access_token=${access_token}`)
        ctx.body = user.data
    } catch (e) {
        ctx.body = { error_description: e.message };
        ctx.status = e.response.status;
    }
});

```

重启app和api服务器，`yarn run app` & `yarn run api`，重复第一步的授权，不出意外我们将会看到如下json:

```
{
    user: {
        id: 1
    },
    client: {
        id: "client"
    }
}
```

步骤F成功了，拿到了受保护的资源，并且API服务器知道是来自哪个`client`，哪个`user`

---

## 总结

本文首先阐述实现`OAuth2`的关键点是RFC6749，很多文章上来就讲什么是`OAuth2`却不提RFC6749，这会误导新手，即使知道了原理，还是不知道请求的参数应该填什么。

其次，我们使用`node`的包`oauth2-server`来实现了一遍授权码验证过程，这个过程要始终围绕RFC6749，否则流程很难走通，自然无法实现`model`。

最后，写这篇文章的缘由是我发现网络上关于`oauth2-server`的koa实现非常非常少，即使有，也没有提供代码，所以就有了这篇文章，源码在[github](https://github.com/wuyunhua1987/koa2-oauth2-server-demo)/[gitee](https://gitee.com/wuyunhua/koa2-oauth2-server-demo)上，希望大家能有所收获。