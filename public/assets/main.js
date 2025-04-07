async function register() {
  // ユーザ名を取得する (idがusernameのinputから)
  const id = document.getElementById('username').value;
  const res = await fetch('registerRequest?id=' + id);
  const options = await res.json();
  const publicKeyCredentialCreationOptions = PublicKeyCredential.parseCreationOptionsFromJSON(options);
  const credential = await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions
  });

  // 取得したクレデンシャルをサーバに送信する
  const credentialJSON = credential.toJSON();
  const credentialStr = JSON.stringify(credentialJSON);
  const fetchOptions = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: credentialStr
  };
  const response = await fetch('/registerResponse', fetchOptions);
  if (response.ok) {
    alert('登録成功');
  } else {
    alert('登録失敗');
  }
}

async function login() {
  const request = await fetch('/loginRequest');
  const options = await request.json();

  const publicKeyCredentialRequestOptions = PublicKeyCredential.parseRequestOptionsFromJSON(options);
  const credential = await navigator.credentials.get({
    publicKey: publicKeyCredentialRequestOptions
  });

  const credentialJSON = credential.toJSON();
  const credentialStr = JSON.stringify(credentialJSON);

  const fetchOptions = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: credentialStr
  };
  const response = await fetch('/loginResponse', fetchOptions);
  if (response.ok) {
    alert('ログイン成功');
  } else {
    alert('ログイン失敗');
  }
}


(async () => {
// デバイス内蔵パスキーを利用可能か？
if (window.PublicKeyCredential && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
  const isUVPAA = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  if (isUVPAA) {
      console.log('UVPAA is available');
  } else {
      console.log('UVPAA is not available');
  }
}

// フォームオートフィルログインのパスキーの認証を利用可能か？ 
if (window.PublicKeyCredential && PublicKeyCredential.isConditionalMediationAvailable) {
  const isCMA = await PublicKeyCredential.isConditionalMediationAvailable();
  if (isCMA) { 
    console.log('CMA is available');
  } else {
    console.log('CMA is not available');
  }
}
})();
