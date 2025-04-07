import express from 'express'
import { JSONFilePreset } from 'lowdb/node'
const db = await JSONFilePreset('db.json', { credentials: [], users: []})
const { credentials, users } = db.data

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

import { isoBase64URL } from '@simplewebauthn/server/helpers';

import session from 'express-session';

const app = express();
app.use(session({
  secret: 'use passkey!',
  resave: true,
  saveUninitialized: true
}));
app.use(express.json());

// static ファイルのサーブをする
app.use(express.static('public'))

// viewエンジンの設定
// handlebarsを使う
import { engine } from 'express-handlebars';
app.engine('hbs', engine({
  extname: 'hbs'
}));
app.set('view engine', 'hbs');
app.set('views', './views');


app.get('/', (req, res) => {
  res.render('index')
})

app.get('/secure', (req, res) => {
  console.log(req.session)
  if (req.session.loginUser) {
    res.send('Hello ' + req.session.loginUser.id);
  } else {
    res.send('Not logged in');
  }
})

// ログインページの表示
app.get('/register', (req, res) => {
  res.render('register')
})

app.get('/login', (req, res) => {
  res.render('login')
})

// 登録開始リクエストのハンドラ
app.get('/registerRequest', async (req, res) => {
  // queryのnameをユーザ名とする
  const { id } = req.query;
  const options = await generateRegistrationOptions({
    rpName:'Example Website',
    rpID: 'localhost',
    userName: id,
    timeout: 300000,
    excludeCredentials:[],
    attestationType: 'direct',
    authenticatorSelection: {
      //authenticatorAttachment: 'cross-platform',
      userVerification: 'required',
    }
  });
  req.session.challenge = options.challenge;
  req.session.user = {
    id,
  }
  return res.json(options);
});

// 登録レスポンスのハンドラ
app.post('/registerResponse', async (req, res) => {
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = 'http://localhost:3000';
  const expectedRPID = 'localhost';

  try {
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      requireUserPresence: true,
      requireUserVerification: false,
    });
    const { verified, registrationInfo } = verification;
    if (!verified) {
      throw new Error('User verification failed');
    }
    console.log(registrationInfo)

    const { credential, userVerified, aaguid, credentialDeviceType } = registrationInfo;
    const base64PublicKey = isoBase64URL.fromBuffer(credential.publicKey);

    const { user } = req.session;

    if (!userVerified) {
      // user verification がpreferred の場合はくる
      // user verify されたのかどうかチェックしたければここでやる
      console.log('user not verified on client');
    } else {
      console.log('user verified on client');
    }

    // DB更新
    const cred = {
      id: credential.id,
      publicKey: base64PublicKey,
      counter: credential.counter,
      transports: credential.transports,
      credentialDeviceType,
      aaguid,
      registered: (new Date()).getTime(),
      last_used: null,
      user_id: user.id,
    };
    await db.update(({credentials}) => credentials.push(cred));

    const newUser = {
      id: user.id,
      created: (new Date()).getTime(),
    }
    await db.update(({users}) => users.push(newUser));

    // dbのcredentialsを表示
    console.log('credentials:', db.data.credentials);
    console.log('users:', db.data.users);

    return res.json({status: 'registered'});
  } catch (err) {
    return res.status(400).json({ error: err.message });
  } finally {
    delete req.session.challenge;
  }
});


// ログイン開始リクエストのハンドラ
app.get('/loginRequest', async (req, res) => {
  const allowCredentials = []; // 再認証の場合

  const options = await generateAuthenticationOptions({
    rpID: 'localhost',
    allowCredentials,
    timeout: 300000,
    userVerification: 'required',
  });

  req.session.challenge = options.challenge;
  return res.json(options);
});

// ログインレスポンスのハンドラ
app.post('/loginResponse', async (req, res) => {
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = 'http://localhost:3000';
  const expectedRPID = 'localhost';

  try {
    const cred = credentials.find((cred) => cred.id === req.body.id);
    if (!cred) {
      throw new Error('Credential not found');
    }
    const user = users.find((user) => user.id === cred.user_id);
    if (!user) {
      throw new Error('User not found');
    }

    const authenticator = {
      publicKey: isoBase64URL.toBuffer(cred.publicKey),
      id: isoBase64URL.toBuffer(cred.id),
    }

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      authenticator,
      credential: {
        id: cred.id,
        publicKey: isoBase64URL.toBuffer(cred.publicKey),
        counter: cred.counter,
        transports: cred.transports,
      },
      requireUserVerification: false,
    });

    const { verified, authenticationInfo } = verification;
    const { userVerified } = authenticationInfo;

    if (!userVerified) {
      // user verification がpreferred の場合はくる
      // user verify されたのかどうかチェックしたければここでやる
      console.log('user not verified on client');
    } else {
      console.log('user verified on client');
    }

    if (!verified) {
      throw new Error('User verification failed');
    }

    // DB更新
    await db.update(({credentials}) => {
      const cred = credentials.find((cred) => cred.id === req.body.id);
      if (cred) {
        cred.last_used = (new Date()).getTime();
      }
      return credentials;
    })

    // ログイン状態とする
    req.session.loginUser = user; 
    return res.json({status: 'logined'})
  } catch (err) {
    console.log(err);
    return res.status(400).json({ error: err.message });
  } finally {
    delete req.session.challenge;
  }
});

app.listen(3000)
