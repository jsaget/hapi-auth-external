'use strict'

import Boom from '@hapi/boom'
import jwtDecode from 'jwt-decode'

export const defaultOptions = {
  methods: {
    attachProvider: () => {},
    checkIfProviderIdentityAlreadyUsed: () => {}
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
          if (!request.auth.isAuthenticated) {
            // cant happened normally because route is authenticated by provider strategy
            throw Boom.unauthorized('External authentication failed. ' + request.auth.error.message)
          }

          const {email, id } = request.auth.credentials.profile
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
      const isExist  = server.methods[options.methods.checkIfProviderIdentityAlreadyUsed]('google', { userId: id })
      if (isExist) {
        console.log('IS ALREADY LINKED')
        throw new Error('External account already attached on another account')
      }

      await server.methods[options.methods.attachProvider](decoded._id, 'google', { userId: id, email })
      return h.response({ status: 'OK' })
    }
  })
}

const plugin = {
  name: 'hapi-auth-external',
  version: '1.0.0',
  dependencies: ['@hapi/bell', 'hapi-auth-jwt'],
  once: true,
  register,
}

export default plugin
