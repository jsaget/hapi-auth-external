'use strict'

import Boom from '@hapi/boom'
import Joi from '@hapi/joi'
import jwtDecode from 'jwt-decode'

const schemaOptions = Joi.object({
  methods: Joi.object({
    attachProvider: Joi.string().required(),
    checkIfProviderIdentityAlreadyUsed: Joi.string().required(),
  }),
  activeAuth: Joi.object({
    // boolean
  }),
  providers: Joi.object({})
})

const register = async (server, options = {}) => {
  schemaOptions.validate(options)

  async function registerProviderRoute(providerName) {
    server.app.logger.debug('Register provider route', providerName, options.providers[providerName])

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

          const resp = await server.inject({
            method: 'GET',
            url: `/api/v1/auth/profile?provider=${providerName}${qs}`,
            allowInternals: true,
            auth: {
              strategy: 'jwt',
              credentials: {
                scope: ['auth'],
              },
            },
          })

          if (!resp) {
            return Boom.unauthorized('INVALID_CREDENTIAL')
          }

          const token = resp.result
          return h.response(token).header('Authorization', 'Bearer: ' + token)
        },
      },
    })

    server.route({
      method: 'GET',
      path: `/attach-${providerName}-provider`,
      options: {
        auth: {
          mode: 'try',
          strategy: providerName,
          access: {
            scope: false,
          },
        },
      },
      handler: async (request, h) => {
        server.app.logger.debug(`route: /attach-${providerName}-provider`, request.query)

        if (!request.auth.isAuthenticated) {
          // cant happened normally because route is authenticated by provider strategy
          throw Boom.unauthorized('External authentication failed. ' + request.auth.error.message)
        }

        const {email, id } = request.auth.credentials.profile
        const token = request.auth.credentials.query.mytoken
        var decoded = jwtDecode(token)

        // search if already linked on another account
        const isExist  = server.methods[options.methods.checkIfProviderIdentityAlreadyUsed](providerName, { userId: id, email })
        if (isExist) {
          throw new Error('External account already attached on another account')
        }

        await server.methods[options.methods.attachProvider](decoded._id, providerName, { userId: id, email })
        return h.response({ status: 'OK' })
      }
    })

    server.app.logger.info(`Provider '${providerName}' loaded`)
  }

  for (const attr in options.providers) {
    if (!options.activeAuth[attr]) {
      continue
    }

    if (!options.providers[attr]) {
      server.app.logger.error(`Failed to load provider ${attr} because there is no configuration for this one`)
      continue
    }

    await registerProviderRoute(attr)
  }
}

const plugin = {
  name: 'hapi-auth-external',
  version: '1.0.0',
  dependencies: ['@hapi/bell', 'hapi-auth-jwt'],
  once: true,
  register,
}

export default plugin
