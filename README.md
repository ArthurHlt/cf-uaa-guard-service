# UAA Auth Route Service [![Build Status](https://travis-ci.org/cloudfoundry-community/cf-uaa-guard-service.svg?branch=master)](https://travis-ci.org/cloudfoundry-community/cf-uaa-guard-service)

**Important Note**: This is a more advanced version of [cloudfoundry-community/cf-uaa-guard-service](https://github.com/cloudfoundry-community/cf-uaa-guard-service).
This version provide a role based authentication through users scopes, a session expiration mechanism (based on token expiration) and [useful endpoints for developpers](#useful-endpoints).

(Based on https://github.com/benlaplanche/cf-basic-auth-route-service)

Using the new route services functionality available in Cloud Foundry, you can now bind applications to routing services.
Traffic sent to your application is routed through the bound routing service before continuing onto your service.

This allows you to perform actions on the HTTP traffic, such as enforcing authentication, rate limiting or logging.

For more details see:
* [Route Services Documentation](http://docs.cloudfoundry.org/services/route-services.html)

## Getting Started

There are two components and thus steps to getting this up and running. The broker and the filtering proxy.

Before getting started you will need:

- Access to a cloud foundry deployment
- UAA client credentials

First, run in command line `install.sh` to install dependencies.

Uncomment and fill in the environment variables required as the sample in `manifest.yml.sample` and copy the manifest to `manifest.yml`.

Run `cf push` to deploy both apps.

Once the broker is deployed, you can register it:

```sh
cf create-service-broker \
    uaa-auth-broker \
    $GUARD_BROKER_USERNAME \
    $GUARD_BROKER_PASSWORD \
    https://uaa-guard-broker.my-paas.com \
    --space-scoped
```

Once you've created the service broker, you must `enable-service-access` in
order to see it in the `marketplace`.

```sh
cf enable-service-access uaa-auth
```

You should now be able to see the service in the marketplace if you run `cf marketplace`

### Protecting an application with UAA authentication

Now you have setup the supporting components, you can now protect your application with auth!

First create an instance of the service from the marketplace, here we are calling our instance `authy`
```
$cf create-service uaa-auth uaa-auth authy
```

Next, identify the application and its URL which you wish to protect. Here we have an application called `hello` with a URL of `https://hello.my-paas.com`

Then you need to bind the service instance you created called `authy` to the `hello.my-paas.com` route
```
⇒  cf bind-route-service my-paas.com authy --hostname hello

Binding may cause requests for route hello.my-paas.com to be altered by service instance authy. Do you want to proceed?> y
Binding route hello.my-paas.com to service instance authy in org org / space space as admin...
OK
```

You can validate the route for `hello` is now bound to the `authy` service instance
```
⇒  cf routes
Getting routes for org org / space space as admin ...

space          host                domain            port   path   type   apps                service
space          hello               my-paas.com                            hello               authy
```

All of that looks good, so the last step is to validate we can no longer view the `hello` application without providing credentials!

```
⇒  curl -k https://hello.my-paas.com
Unauthorized
```

and if you visit it you will be redirected to UAA.

### Knowing who is logged in

This service will forward a set of headers:

- `Authorization` with the bearer token.
- `X-Auth-User` with the email of the logged in user.
- `X-Auth-User-Email` with the email of the logged in user.
- `X-Auth-User-Name` with the name of the logged in user.
- `X-Auth-User-Id` with the uuid of the logged in user.
- `X-Auth-User-Scopes` with a list of scopes of the logged in user (separate by a `,`).

## Add a proxy to only make your app accessible by a cloud foundry admin

As an administrator you will maybe need to restrict access to some apps in order to only make them usable
 by other administrator.

The proxy has a mechanism of roles based on scopes. If a user doesn't have a required scopes he will be rejected by the proxy.

Let's have a look to an manifest example:

```yml

---
buildpack: go_buildpack
applications:
  - name: uaa-guard-proxy-users
    path: proxy
    memory: 128M
    env:
      GUARD_COOKIE_SECRET: very-secret
      GUARD_LOGIN_URL: https://login.my-paas.com
      GUARD_CLIENT_KEY: uaa-guard-oauth
      GUARD_CLIENT_SECRET: yoursecret
      GUARD_PROXY_NAME: uaa-users-auth
      GUARD_PROXY_DESCRIPTION: "Just add to a route and it will request cloud foundry authentication before proceeding and let any users registered on cloud foundry login."
      GUARD_SCOPES: "openid"
  - name: uaa-guard-proxy-admin
    path: proxy
    memory: 128M
    env:
      GUARD_COOKIE_SECRET: very-secret
      GUARD_LOGIN_URL: https://login.my-paas.com
      GUARD_CLIENT_KEY: uaa-guard-admin-oauth
      GUARD_CLIENT_SECRET: yoursecret
      GUARD_PROXY_NAME: uaa-admin-auth
      GUARD_PROXY_DESCRIPTION: "Just add to a route and it will request cloud foundry authentication before proceeding and let only admin registered on cloud foundry login."
      GUARD_SCOPES: "openid,cloud_controller.admin"
  - name: uaa-guard-broker
    path: broker
    memory: 64M
    env:
      GUARD_BROKER_NAME: uaa-auth
      GUARD_BROKER_USERNAME: broker
      GUARD_BROKER_PASSWORD: broker
      GUARD_ROUTE_SERVICE_URLS: https://uaa-guard-proxy-users.my-paas.com,https://uaa-guard-proxy-admin.my-paas.com
```

the app `uaa-guard-proxy-admin` has a second scope (`cloud_controller.admin`) it means that user will need
 to have the `cloud_controller.admin` scope in order to login to the app.

The broker has a second route service urls, it will add a new plan to the broker based on the name of the proxy.

To update the catalog of the service broker in cloud foundry run:

```sh
cf update-service-broker \
    uaa-auth-broker \
    $GUARD_BROKER_USERNAME \
    $GUARD_BROKER_PASSWORD \
    https://uaa-guard-broker.my-paas.com \
    --space-scoped
```

## Useful endpoints

- `/me` *(e.g.: `https://hello.my-paas.com/me`)*: Give information of a logged user in a json format (this useful for frontend developper), example of json:
```json
{
	"scope": [
		"openid"
	],
	"user_id": "c434a43b-a165-4019-b24d-5af8103028d9",
	"user_name": "arthurhlt",
	"exp": 1487136414,
	"email": "arthur.halet@orange.com",
	"token_type": "bearer",
	"access_token": "ajwttoken"
}
```
- `/logout` *(e.g.: `https://hello.my-paas.com/logout`)*: By calling this endpoint it will logout the connected user.