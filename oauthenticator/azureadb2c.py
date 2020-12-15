"""
Custom Authenticator to use Azure AD B2C with JupyterHub
"""

import json
import jwt
import os
import urllib

from tornado.auth import OAuth2Mixin
from tornado.httpclient import HTTPClientError
from tornado.log import app_log
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, default

from .oauth2 import OAuthLoginHandler, OAuthenticator


class AzureAdB2COAuthenticator(OAuthenticator):
    login_service = Unicode(
		os.environ.get('LOGIN_SERVICE', 'Azure AD B2C'),
		config=True,
		help="""Azure AD domain name string, e.g. My College"""
	)

    tenant_id = Unicode(config=True, help="The Azure Active Directory B2C Tenant ID of the format: yourb2ctenantname.onmicrosoft.com")
    tenant_id_short = Unicode(config=True, help="The Azure Active Directory B2C Tenant ID short form: eg, if long form is asdf.onmicrosoft.com, this would be asdf. This will be automatically generated from tenant_id if not set.")
    b2c_profile_name = Unicode(config=True, help="The Azure Active Directory B2C Profile Name (eg: B2C_1A_SignUpOrSignInWithAAD")

    @default('tenant_id')
    def _tenant_id_default(self):
        return os.environ.get('AAD_TENANT_ID', '')
      
    @default('tenant_id_short')
    def _tenant_id_short_default(self):
        return os.environ.get('AAD_TENANT_ID', '').split('.')[0]
    
    @default('b2c_profile_name')
    def _b2c_profile_name_default(self):
        return os.environ.get('AAD_B2C_PROFILE_NAME', '')

    username_claim = Unicode(config=True)

    @default('username_claim')
    def _username_claim_default(self):
        return 'name'

    @default("authorize_url")
    def _authorize_url_default(self):
        return 'https://{0}.b2clogin.com/{1}/oauth2/authorize?p={2}&scope=openid'.format(self.tenant_id_short, self.tenant_id, self.b2c_profile_name)

    @default("token_url")
    def _token_url_default(self):
        return 'https://{0}.b2clogin.com/{1}/oauth2/token?p={2}&scope=openid'.format(self.tenant_id_short, self.tenant_id, self.b2c_profile_name)

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        http_client = AsyncHTTPClient()

        params = dict(
            client_id=self.client_id,
            #client_secret=self.client_secret,
            grant_type='authorization_code',
            code=code,
            redirect_uri=self.get_callback_url(handler))

        data = urllib.parse.urlencode(
            params, doseq=True, encoding='utf-8', safe='=')

        url = self.token_url

        headers = {
            'Content-Type':
            'application/x-www-form-urlencoded; charset=UTF-8'
        }
        req = HTTPRequest(
            url,
            method="POST",
            headers=headers,
            body=data  # Body is required for a POST...
        )

        app_log.info("About to POST to token url: %s", url)
        app_log.info("Headers are: %s", headers)
        app_log.info("POST body data is: %s", data)

        try:
            resp = await http_client.fetch(req)
        except HTTPClientError as e:
            app_log.error("HTTPClientError thrown during POST to token url")
            
            if e.code is None:
                app_log.error("Exception code is None")
            else:
                app_log.error("Exception HTTPResponse code is: %s", e.code)
            
            if e.response is None:
                app_log.error("Exception HTTPResponse object is None")
            else:
                app_log.error("Exception HTTPResponse reason is: %s", e.response.reason)
                app_log.error("Exception HTTPResponse body is: %s", e.response.body)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        # app_log.info("Response %s", resp_json)
        access_token = resp_json['access_token']

        id_token = resp_json['id_token']
        decoded = jwt.decode(id_token, verify=False)

        userdict = {"name": decoded[self.username_claim]}
        userdict["auth_state"] = auth_state = {}
        auth_state['access_token'] = access_token
        # results in a decoded JWT for the user data
        auth_state['user'] = decoded

        return userdict


class LocalAzureAdB2COAuthenticator(LocalAuthenticator, AzureAdB2COAuthenticator):
    """A version that mixes in local system user creation"""
    pass
