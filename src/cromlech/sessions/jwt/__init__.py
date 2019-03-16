# -*- coding: utf-8 -*-

import os
from functools import wraps
from biscuits import parse, Cookie
from datetime import datetime, timedelta
from cromlech.jwt.components import JWTService, JWTHandler, ExpiredToken
from cromlech.browser import getSession,setSession
from cromlech.jwt import InvalidToken

load_key = JWTHandler.load_key


def key_from_file(path, create=True):
    fullpath = os.path.abspath(path)
    if not os.path.isfile(fullpath):
        if create:
            key = JWTHandler.generate_key()
            with open(fullpath, 'w+', encoding="utf-8") as keyfile:
                keyfile.write(JWTHandler.dump_key(key))
            return key
        else:
            raise OSError('Key file could not be found.')
    else:
        with open(fullpath, 'r') as fd:
            key_data = fd.read()
            key = JWTHandler.load_key(key_data)
    return key


class JWTCookieSession(JWTService):

    def __init__(self, key, lifetime, cookie_name="jwt", environ_key="session"):
        self.cookie_name = cookie_name
        self.environ_key = environ_key
        JWTService.__init__(self, key, JWTHandler, lifetime=lifetime)

    def extract_session(self, environ):
        cookie = environ.get('HTTP_COOKIE')
        if cookie is not None:
            morsels = parse(cookie)
            token = morsels.get(self.cookie_name)
            if token is not None:
                try:
                    session_data = self.check_token(token)
                    return session_data
                except (ExpiredToken,InvalidToken) as e:
                    # The token is expired.
                    # We'll return an empty session.
                    pass
        return {}

    def check_cookie_size(self, value, maxsize=4096):
        if len(value) > maxsize:
            raise ValueError('Cookie exceeds the %i bytes limit' % maxsize)

    def __call__(self, app):
        @wraps(app)
        def jwt_session_wrapper(environ, start_response):

            def session_start_response(status, headers, exc_info=None):
                session_data = environ[self.environ_key]
                path = environ['SCRIPT_NAME'] or '/'
                domain = environ['HTTP_HOST'].split(':', 1)[0]

                #if there is no registered user
                #then delete the cookie on the client.
                #by setting the contents to be the empty string
                #and the expires time to be now.
                
                if  session_data:
                   token = self.generate(session_data)
                   expires = datetime.now() + timedelta(minutes=self.lifetime)
                else:
                   token =''
                   expires = datetime.now()

                cookie = Cookie(
                    name=self.cookie_name, value=token, path=path,
                    domain=domain, expires=expires)
                cookie_value = str(cookie)
                self.check_cookie_size(cookie_value)
                headers.append(('Set-Cookie', cookie_value))
                return start_response(status, headers, exc_info)
            
            session = self.extract_session(environ)
            environ[self.environ_key] = session
            return app(environ, session_start_response)
        return jwt_session_wrapper


__all__ = (
    'load_key_file', 'load_key_string', 'generate_key', 'JWTCookieSession')
