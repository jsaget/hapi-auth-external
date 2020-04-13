'use strict'

import Boom from '@hapi/boom'
import jwtDecode from 'jwt-decode'

import {attachProvider, checkIfProviderIdentityAlreadyUsed} from '../../models/users.mjs'

const options = {
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

const register = async (server, options = {}) => {

  async function registerProviderRoute(providerName) {
    console.log('getRoute', providerName, options.providers[providerName])
    server.auth.strategy(providerName, 'bell',  options.providers[providerName]);
    server.route({
      method: 'GET',
      path: '/' + providerName,
      options: {
        auth: {
          strategy: providerName,
          access: {
            scope: false,
          },
        },
        handler: async function(request, h) {
          // console.log('CRED', request.auth.credentials)
          if (!request.auth.isAuthenticated) {
            // cant happened normally because route is authenticated by provider strategy
            throw Boom.unauthorized('External authentication failed. ' + request.auth.error.message)
          }

          const {email, id } = request.auth.credentials.profile
          // console.log('profile', request.auth.credentials.profile)
          // console.log('credential', request.auth.credentials)
          let qs = undefined
          if (id) {
            qs = `&userId=${id}`
          }
          if (!qs && email) {
            qs = `&email=${email}`
          }

          console.log('Fetch profile ...', providerName, email, id, qs)
          const resp = await server.inject({
            method: 'GET',
            url: `/api/v1/auth/profile?provider=${providerName}${qs}`,
            allowInternals: true,
            auth: {
              strategy: 'jwt',
              credentials: {
                scope: ['auth']
              }
            },
          })

          if (!resp) {
            return Boom.unauthorized('INVALID_CREDENTIAL')
          }

          console.log('rESP', resp.result)
          const token = resp.result
          return h.response(token)
            .header('Authorization', 'Bearer: ' + token)
        },
      },

    })

    console.log(`Provider '${providerName}' loaded`)
  }

  for (const attr in options.providers) {
    if (!options.activeAuth[attr]) {
      continue
    }

    if (!options.providers[attr]) {
      console.log(`Failed to load provider ${attr} because there is no configuration for this one`)
      continue;
    }

    await registerProviderRoute(attr)
  }


    server.route({
    method: 'GET',
    path: '/attach-provider',
    options: {
      auth: {
        mode: 'try',
        strategy: 'google',
        // strategy: 'jwt',
        access: {
          scope: false,
        },
      },
      // validate: {
      //   query: Joi.object({
      //     provider: Joi.string().required(),
      //   }),
      // },
    },
    handler: async (request, h) => {
      console.log('Route /add-provider', request.query)
      console.log('LALALALA', request.auth.credentials)

      if (!request.auth.isAuthenticated) {
        console.log('NOT AUHTN')
        // cant happened normally because route is authenticated by provider strategy
        throw Boom.unauthorized('External authentication failed. ' + request.auth.error.message)
      }

      const {email, id } = request.auth.credentials.profile
      const token = request.auth.credentials.query.mytoken
      var decoded = jwtDecode(token);

      // search if already linked on another account
      console.log('CHEC IF ATTACHED')
      const isExist  = await checkIfProviderIdentityAlreadyUsed('google', { userId: id })
      if (isExist) {
        console.log('IS ALREADY LINKED')
        throw new Error('External account already attached on another account')
      }

      const data = { _id: decoded._id, provider: {name: 'google', userId: id, email }}
      console.log('data ##', data)
      await attachProvider(decoded._id, {provider: 'google', userId: id, email })

      console.log('###################### OKKKKKKKKKKKKKKKKKKKK')
      return h.redirect('/home')
    }
  })
}


const plugin = {
  name: 'auth-external',
  version: '1.0.0',
  dependencies: ['@hapi/bell'],
  once: true,
  register,
}

export default plugin



/*

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

*/

