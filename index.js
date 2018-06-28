var url = require('url');
var bodyParser = require('body-parser');
var expressJwt = require('express-jwt');
var rsaValidation = require('auth0-api-jwt-rsa-validation');
var ejs = require('ejs');
var app = new(require('express'))();
var crypto = require('crypto');

const getModules = () => {
  const Path = require('path');

  const abcsort = function (a, b) {
    if (a.name < b.name) {
      return -1;
    }

    if (a.name > b.name) {
      return 1;
    }

    return 0;
  };


  const natives = Object.keys(process.binding("natives"))
    .filter(nativeDep => nativeDep[0] !== '_')
    .map(dep => ({
      name: dep,
      version: 'native'
    }))
    .sort(abcsort);

  const manifest = require(Path.join(process.env.VERQUIRE_DIR, 'packages.json'));

  const modules = Object.keys(manifest).reduce((acc, module_name) => {
      const versions = manifest[module_name];

      versions.forEach((version) => {
        const moduleObj = {
          name: module_name,
          version: version
        };

        acc.push(moduleObj);
      });

      return acc;
    }, [])
    .sort(abcsort);

  return {
    node_version: process.version,
    modules: natives.concat(modules)
  }
}

app.use(function (req, res, next) {
  var xfproto = req.get('x-forwarded-proto');

  req.baseUrl = [
    xfproto ? xfproto.split(',')[0].trim() : 'https',
    '://',
    req.get('host'),
    url.parse(req.originalUrl).pathname
  ].join('');
  req.audience = 'https://'+req.webtaskContext.data.AUTH0_DOMAIN+'/api/v2/';

  next();
});

app.get('/', function (req, res) {
  res.redirect([
    req.webtaskContext.data.AUTH0_RTA || 'https://auth0.auth0.com', '/authorize',
    '?client_id=', req.baseUrl,
    '&response_type=token&expiration=86400000&response_mode=form_post',
    '&scope=', encodeURIComponent('openid profile'),
    '&redirect_uri=', req.baseUrl,
    '&audience=', req.audience,
    '&nonce=' + encodeURIComponent(crypto.randomBytes(16).toString('hex'))
  ].join(''));
});

app.get('/.well-known/oauth2-client-configuration', function (req, res) {
  res.json({
    redirect_uris: [req.baseUrl.replace('/.well-known/oauth2-client-configuration', '')],
    client_name: 'Auth0 Extension',
    post_logout_redirect_uris: [req.baseUrl.replace('/.well-known/oauth2-client-configuration', '')]
  });
});

app.post('/',
  bodyParser.urlencoded({
    extended: false
  }),
  expressJwt({
    secret: rsaValidation({
      strictSSL: true
    }),
    algorithms: ['RS256'],
    getToken: req => req.body.access_token
  }),
  function (req, res) {
    if (req.user.aud === req.audience || Array.isArray(req.user.aud) && req.user.aud.indexOf(req.audience) > -1) {
      res.send(ejs.render(homeTemplate, {
        container: req.x_wt.container,
        modules: getModules()
      }));
    } else {
      res.status(403);
      res.send(ejs.render(notAuthorizedTemplate, {
        baseUrl: req.baseUrl
      }));
    }
  });

app.get('/meta', function (req, res) {
  // Keep this manually in sync with webtask.json (to avoid bundling step)
  res.json({
    "title": "Can I Require Extension",
    "name": "canirequire-extension",
    "version": "1.0.0",
    "author": "Auth0, Inc",
    "description": "Discover which modules you can require in Auth0 extensibility points",
    "type": "application",
    "repository": "https://github.com/auth0-extensions/canirequire-extension",
    "keywords": [
      "auth0",
      "extension",
      "webtask",
      "canirequire"
    ]
  });
});

app.get('/logout', function (req, res) {
  res.send(ejs.render(logoutTemplate, {
    container: req.x_wt.container,
    baseUrl: req.baseUrl
  }));
});

function s(f) {
  return f.toString().match(/[^]*\/\*([^]*)\*\/\s*\}$/)[1];
}

var logoutTemplate = s(function () {
  /*
  <html>
    <head>
      <script>
        window.location.href = 'https://auth0.auth0.com/logout?returnTo=<%- baseUrl.replace('logout', '/')%>&client_id=<%- baseUrl.replace('logout', '/')%>';
      </script>
    </head>
    <body></body>
  </html>
  */
});

var notAuthorizedTemplate = s(function () {
  /*
  <!DOCTYPE html5>
  <html>
    <head>
      <meta charset="utf-8"/>
      <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <link rel="shortcut icon" href="https://cdn.auth0.com/styleguide/2.0.1/lib/logos/img/favicon.png">
      <link href="https://cdn.auth0.com/styleguide/latest/index.css" rel="stylesheet" />
      <title>Access denied</title>
    </head>
    <body>
      <div class="container">
        <div class="row text-center">
          <h1><a href="https://auth0.com" title="Go to Auth0!"><img src="https://cdn.auth0.com/styleguide/1.0.0/img/badge.svg" alt="Auth0 badge" /></a></h1>
          <h1>Not authorized</h1>
          <p><a href="https://auth0.auth0.com/logout?returnTo=<%- baseUrl %>">Log out from Auth0 and try again</a></p>
        </div>
      </div>
    </body>
  </html>
  */
});

var homeTemplate = s(function () {
  /*
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>Can I require?</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0-rc.2/css/materialize.min.css">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <link rel="stylesheet" href="https://auth0-extensions.github.io/canirequire/style.css">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no"/>
    <script>
      window.wtModuleList = <%- JSON.stringify(modules) %>
    </script>
  </head>
  <body>
    <nav class="white" role="navigation">
      <div class="nav-wrapper container">
      </div>
    </nav>
    <div class="white" id="index-banner">
      <div class="container">
        <br><br>
        <h1 class="header center grey-text lighten-5-text">Can I require: <span class="webtask-red-text">Auth0 Extensibility</span></h1>
        <div class="row">
          <div class="col s12 input-field" id="canirequire-search">
            <label>Search for a module</label>
            <input type="text" class="input-main grey-text webtask-red-border" placeholder="e.g. mongodb" name="modules-filter">
          </div>
        </div>
        <br><br>
      </div>
    </div>
    <section id="canirequire-modules">
    </section>
    <script
      src="https://code.jquery.com/jquery-3.3.1.min.js"
      integrity="sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8="
      crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0-rc.2/js/materialize.min.js"></script>
    <script type="text/javascript" src="https://auth0-extensions.github.io/canirequire/canirequire.js" ></script>
  </body>
  */
});

module.exports = require('webtask-tools').fromExpress(app);