# hapi-auth-external


```js
export const defaultOptions = {
  methods: {
    attachProvider: '',
    checkIfProviderIdentityAlreadyUsed: '',
  },
  activeAuth: {
    google: true,
    github: false,
    twitter: false,
    facebook: false,
  },

  providers: {
    facebook: {
      provider: 'facebook',
      password: 'AUTH_BELL_KEY',
      clientId: 'AUTH_FACEBOOK_CLIENT_ID',
      clientSecret: 'AUTH_FACEBOOK_CLIENT_SECRET',
      isSecure: process.env.NODE_ENV === 'production',
      forceHttps: process.env.NODE_ENV === 'production',
    },
    google: {
      provider: 'google',
      password: 'AUTH_BELL_KEY',
      clientId: 'AUTH_GOOGLE_CLIENT_ID',
      clientSecret: 'AUTH_GOOGLE_CLIENT_SECRET',
      isSecure: process.env.NODE_ENV === 'production',
      forceHttps: process.env.NODE_ENV === 'production',
    },
    github: {
      provider: 'github',
      location: 'http://localhost:3000',
      password: 'AUTH_BELL_KEY',
      clientId: 'AUTH_GITHUB_CLIENT_ID',
      clientSecret: 'AUTH_GITHUB_CLIENT_SECRET',
      isSecure: process.env.NODE_ENV === 'production',
      forceHttps: process.env.NODE_ENV === 'production',
    },
    twitter: {
      provider: 'twitter',
      password: 'AUTH_BELL_KEY',
      clientId: 'AUTH_TWITTER_CLIENT_ID',
      clientSecret: 'AUTH_TWITTER_CLIENT_SECRET',
      isSecure: process.env.NODE_ENV === 'production',
      forceHttps: process.env.NODE_ENV === 'production',
    },
  },
}
```


```
  Idée
  En du coup ça marche bien aussi en oauth :
  1/ L'user est dirigé sur la page /auth/oauth/google
  2/ L'user est redirigé sur le serveur d'auth de google et s'authentifie
  3/ Il est redirigé sur /auth/oauth/google avec plein de params en plus
  4/ Le plugin d'auth fait une requête sur /user/auth?type=oauth_google&data={id: idgoogle}
  5/ Le serveur répond par ex : {username: toto, scope: user, email: xxx, avatar: url}
  6/ Le plugin rajoute à ces données les données techniques du token (issuer / expiration / etc) et génère le token
  7/ Le plugin redirige l'user sur la page où il était avant en rajoutant ?token=token à l'URL
  Tu peux enlever la charge tant que tu sais que c'est chez toi en utilisant server.inject au lieu de faire une requête HTTP full.
  Tu pourrais mm mettre une config sur ton plugin pour lui dire si il faut faire du server.inject au lieu d'une requête.
  Ou le décider en fct de l'URL donnée en param !!!
  Si tu mets une URL complète, genre https://domain.com/user/auth, dans ce cas c'est requête HTTP(S), si tu mets juste un chemin, genre /user/auth, c'est server.inject qui est utilisé.
  C'est assez sexy comme approche.
  Comme ça, le plugin s'auto-optimise avec juste un petit test, c'est assez facile à mettre en place.
```
