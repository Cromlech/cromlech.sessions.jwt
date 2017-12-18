# -*- coding: utf-8 -*-

from functools import wraps
from biscuits import parse, Cookie
from datetime import datetime, timedelta
from cromlech.jwt.components import JWTService, JWTHandler


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
                session_data = self.check_token(token)
                # maybe we want an error handling here.
                return session_data
        return {}

    def wrapper(self, app):
        @wraps(app)
        def jwt_session_wrapper(environ, start_response):

            def session_start_response(status, headers, exc_info=None):
                session_data = environ[self.environ_key]
                token = self.generate(session_data)
                path = environ['SCRIPT_NAME'] or '/'
                domain = environ['HTTP_HOST'].split(':', 1)[0]
                expires = datetime.now() + timedelta(minutes=self.lifetime)
                cookie = Cookie(
                    name=self.cookie_name, value=token, path=path,
                    domain=domain, expires=expires)
                headers.append(('Set-Cookie', str(cookie)))
                return start_response(status, headers, exc_info)

            session = self.extract_session(environ)
            environ[self.environ_key] = session
            return app(environ, session_start_response)
        return jwt_session_wrapper
