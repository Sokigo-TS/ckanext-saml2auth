# encoding: utf-8

"""
Copyright (c) 2020 Keitaro AB

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import copy

from flask import Blueprint, session, request, make_response
from urllib.parse import urlparse
from saml2 import entity
from saml2.authn_context import requested_authn_context

import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.plugins as plugins
import ckan.lib.dictization.model_dictize as model_dictize
from ckan.lib import base
from ckan.common import config, g

from ckanext.saml2auth.spconfig import get_config as sp_config
from ckanext.saml2auth import helpers as h
from ckanext.saml2auth.interfaces import ISaml2Auth
from ckanext.saml2auth.cache import set_subject_id, set_saml_session_info


log = logging.getLogger(__name__)
saml2auth = Blueprint(u'saml2auth', __name__)

# Paths that should never be used as post-login redirect targets
# because they are login/register pages themselves
EXCLUDED_RELAY_PATHS = ['/user/login', '/user/register', '/user/_logout']
EXCLUDED_RELAY_ENDPOINTS = ['user.login', 'user.register']


def _is_excluded_relay_state(relay_state):
    """Check if relay_state points to a login/register page we should not
    redirect to."""
    if not relay_state:
        return True

    # Check exact endpoint name matches
    if relay_state in EXCLUDED_RELAY_ENDPOINTS:
        return True

    # Check path-only matches (e.g. /user/login)
    if relay_state in EXCLUDED_RELAY_PATHS:
        return True

    # Check full URL matches — extract path and compare
    try:
        parsed = urlparse(relay_state)
        if parsed.path in EXCLUDED_RELAY_PATHS:
            return True
    except Exception:
        pass

    return False


def _get_requested_authn_contexts():
    requested_authn_contexts = config.get(
        'ckanext.saml2auth.requested_authn_context', None)
    if requested_authn_contexts is None or requested_authn_contexts == '':
        return []
    return requested_authn_contexts.strip().split()


SSO_BINDINGS = {
    u'post': entity.BINDING_HTTP_POST,
    u'redirect': entity.BINDING_HTTP_REDIRECT,
    entity.BINDING_HTTP_POST.lower(): entity.BINDING_HTTP_POST,
    entity.BINDING_HTTP_REDIRECT.lower(): entity.BINDING_HTTP_REDIRECT,
}


def _get_sso_binding():
    u'''Return the binding used to send the AuthnRequest to the IdP.

    HTTP-POST is the default: the browser gets an HTML form that posts the
    request to the IdP, so there is no Location header for a reverse proxy
    to rewrite. HTTP-Redirect sends the request as a 302 with the request
    in the query string.
    '''
    value = config.get(u'ckanext.saml2auth.sso_binding') or u'post'
    binding = SSO_BINDINGS.get(value.strip().lower())
    if binding is None:
        raise ValueError(
            u'Unexpected ckanext.saml2auth.sso_binding value {}, use '
            u'post or redirect'.format(value))
    return binding


def _dictize_user(user_obj):
    context = {
        u'keep_email': True,
        u'model': model,
    }
    user_dict = model_dictize.user_dictize(user_obj, context)
    # Make a copy so SQLAlchemy can track changes properly
    user_dict['plugin_extras'] = copy.deepcopy(user_obj.plugin_extras)
    return user_dict


def _get_user_by_saml_id(saml_id):
    user_obj = model.Session.query(model.User) \
        .filter(model.User.plugin_extras[
            (u'saml2auth', u'saml_id')].astext == saml_id) \
        .first()
    h.activate_user_if_deleted(user_obj)
    return _dictize_user(user_obj) if user_obj else None


def _get_user_by_email(email):
    user = model.User.by_email(email)
    if user and isinstance(user, list):
        user = user[0]
    h.activate_user_if_deleted(user)
    return _dictize_user(user) if user else None


def _update_user(user_dict):
    context = {u'ignore_auth': True}
    try:
        return toolkit.get_action(u'user_update')(context, user_dict)
    except toolkit.ValidationError as e:
        error_message = (e.error_summary or e.message or e.error_dict)
        base.abort(400, error_message)


def _create_user(user_dict):
    context = {u'ignore_auth': True}
    try:
        return toolkit.get_action(u'user_create')(context, user_dict)
    except toolkit.ValidationError as e:
        error_message = (e.error_summary or e.message or e.error_dict)
        base.abort(400, error_message)


def process_user(email, saml_id, full_name, saml_attributes):
    u'''
    Check if a CKAN-SAML user exists for the current SAML login, if not
    create a new one. Returns the user name.
    '''
    user_dict = _get_user_by_saml_id(saml_id)

    if user_dict:
        current_user_dict = copy.deepcopy(user_dict)

        if email != user_dict['email'] or full_name != user_dict['fullname']:
            user_dict['email'] = email
            user_dict['fullname'] = full_name

        for plugin in plugins.PluginImplementations(ISaml2Auth):
            plugin.before_saml2_user_update(user_dict, saml_attributes)

        if current_user_dict != user_dict:
            user_dict = _update_user(user_dict)

        return user_dict['name']

    user_dict = _get_user_by_email(email)

    if user_dict:
        user_dict[u'password'] = h.generate_password()
        user_dict[u'plugin_extras'] = {
            u'saml2auth': {u'saml_id': saml_id}
        }

        for plugin in plugins.PluginImplementations(ISaml2Auth):
            plugin.before_saml2_user_update(user_dict, saml_attributes)

        user_dict = _update_user(user_dict)
        return user_dict['name']

    user_dict = {
        u'name': h.ensure_unique_username_from_email(email),
        u'fullname': full_name,
        u'email': email,
        u'password': h.generate_password(),
        u'plugin_extras': {
            u'saml2auth': {u'saml_id': saml_id}
        }
    }

    for plugin in plugins.PluginImplementations(ISaml2Auth):
        plugin.before_saml2_user_create(user_dict, saml_attributes)

    user_dict = _create_user(user_dict)
    return user_dict[u'name']


def acs():
    u'''The location where the SAML assertion is sent with a HTTP POST.
    This is often referred to as the SAML Assertion Consumer Service (ACS) URL.
    '''
    g.user = None
    g.userobj = None

    saml_user_firstname = config.get(u'ckanext.saml2auth.user_firstname')
    saml_user_lastname = config.get(u'ckanext.saml2auth.user_lastname')
    saml_user_fullname = config.get(u'ckanext.saml2auth.user_fullname')
    saml_user_email = config.get(u'ckanext.saml2auth.user_email')

    client = h.saml_client(sp_config())
    saml_response = request.form.get(u'SAMLResponse', None)

    error = None
    try:
        auth_response = client.parse_authn_request_response(
            saml_response,
            entity.BINDING_HTTP_POST)
    except Exception as e:
        error = 'Bad login request: {}'.format(e)
    else:
        if auth_response is None:
            error = 'Empty login request'

    if error is not None:
        log.error(error)
        extra_vars = {u'code': [400], u'content': error}
        return base.render(u'error_document_template.html', extra_vars), 400

    auth_response.get_identity()
    user_info = auth_response.get_subject()
    session_info = auth_response.session_info()

    saml_id = user_info.text
    email = auth_response.ava[saml_user_email][0]

    if saml_user_firstname and saml_user_lastname:
        first_name = auth_response.ava.get(
            saml_user_firstname, [email.split('@')[0]])[0]
        last_name = auth_response.ava.get(
            saml_user_lastname, [email.split('@')[1]])[0]
        full_name = u'{} {}'.format(first_name, last_name)
    else:
        if saml_user_fullname and saml_user_fullname in auth_response.ava:
            full_name = auth_response.ava[saml_user_fullname][0]
        else:
            full_name = u'{} {}'.format(
                email.split('@')[0], email.split('@')[1])

    g.user = process_user(email, saml_id, full_name, auth_response.ava)
    log.debug("SAML2 acs: process_user returned username: %s", g.user)

    h.update_user_sysadmin_status(g.user, email)

    # Flush so newly created users are visible to the by_name query
    model.Session.flush()
    g.userobj = model.User.by_name(g.user)
    log.debug("SAML2 acs: g.userobj resolved to: %s", g.userobj)

    if g.userobj is None:
        log.error("SAML2 acs: could not find user object for: %s", g.user)
        extra_vars = {
            u'code': [500],
            u'content': 'User login failed - user not found'
        }
        return base.render(u'error_document_template.html', extra_vars), 500

    # Determine redirect target — return the user to where they started
    relay_state = request.form.get('RelayState', '')
    log.debug("SAML2 acs: relay_state received: %s", relay_state)

    default_endpoint = config.get(
        'ckanext.saml2auth.default_fallback_endpoint', 'user.me')

    if _is_excluded_relay_state(relay_state):
        # No usable came-from, or it points at a login/register page
        redirect_target = toolkit.url_for(default_endpoint, _external=True)
        log.debug("SAML2 acs: relay_state excluded, using default: %s",
                  redirect_target)
    else:
        parsed = urlparse(relay_state)
        if parsed.scheme and parsed.netloc:
            # Full absolute URL (e.g. http://localhost:5000/dataset/foo)
            redirect_target = relay_state
        elif parsed.path and parsed.path != '/':
            # A path relative to the site (e.g. /dataset/foo)
            redirect_target = relay_state
        else:
            # Possibly an endpoint name (e.g. 'dataset.read')
            try:
                redirect_target = toolkit.url_for(relay_state, _external=True)
            except Exception:
                redirect_target = toolkit.url_for(
                    default_endpoint, _external=True)

    log.debug("SAML2 acs: final redirect_target: %s", redirect_target)
    resp = toolkit.redirect_to(redirect_target)

    _log_user_into_ckan(resp)

    # Force session save — without this Flask-Session may not
    # write the cookie on redirect responses
    session.modified = True

    set_saml_session_info(session, session_info)
    set_subject_id(session, session_info['name_id'])

    for plugin in plugins.PluginImplementations(ISaml2Auth):
        resp = plugin.after_saml2_login(resp, auth_response.ava)

    return resp


def _log_user_into_ckan(resp):
    """Log the user into CKAN (2.10+ uses flask-login's login_user)."""
    from ckan.common import login_user

    log.debug(
        "SAML2 _log_user_into_ckan: calling login_user with: %s",
        g.userobj
    )

    login_user(g.userobj)

    log.info(
        u'User {0}<{1}> logged in successfully'.format(
            g.userobj.name,
            g.userobj.email
        )
    )

    return


def saml2login():
    u'''Sends the user to the configured identity provider for
    authentication, with an auto-submitting form (HTTP-POST, the default)
    or a redirect (HTTP-Redirect), see ckanext.saml2auth.sso_binding.
    '''
    client = h.saml_client(sp_config())
    requested_authn_contexts = _get_requested_authn_contexts()
    binding = _get_sso_binding()

    relay_state = toolkit.request.args.get('came_from', '')
    log.debug("SAML2 saml2login: came_from arg: %s", relay_state)
    if relay_state == '' and request and request.referrer:
        relay_state = urlparse(request.referrer).path
    log.debug("SAML2 saml2login: relay_state to send to IdP: %s", relay_state)

    # Never send login/register as relay_state to the IdP
    if _is_excluded_relay_state(relay_state):
        relay_state = ''

    if len(requested_authn_contexts) > 0:
        comparison = config.get(
            'ckanext.saml2auth.requested_authn_context_comparison', 'minimum')
        if comparison not in ['exact', 'minimum', 'maximum', 'better']:
            raise ValueError(
                'Unexpected comparison value {}'.format(comparison))

        final_context = requested_authn_context(
            class_ref=requested_authn_contexts,
            comparison=comparison
        )
        reqid, info = client.prepare_for_authenticate(
            requested_authn_context=final_context,
            relay_state=relay_state,
            binding=binding)
    else:
        reqid, info = client.prepare_for_authenticate(
            relay_state=relay_state,
            binding=binding)

    if binding == entity.BINDING_HTTP_POST:
        # An HTML page whose form posts the AuthnRequest to the IdP
        response = make_response(info[u'data'], 200)
        response.headers[u'Content-Type'] = u'text/html; charset=utf-8'
        response.headers[u'Cache-Control'] = u'no-cache, no-store'
        return response

    redirect_url = None
    for key, value in info[u'headers']:
        if key == u'Location':
            redirect_url = value
    return toolkit.redirect_to(redirect_url)


def disable_default_login_register():
    u'''View function used to override and disable default Register/Login
    routes.
    '''
    extra_vars = {
        u'code': [403],
        u'content': (u'This resource is forbidden by the system administrator.'
                     u' Only SSO through SAML2 authorization is available at'
                     u' this moment.')
    }
    return base.render(u'error_document_template.html', extra_vars), 403


def slo():
    u'''View function that handles the IDP logout request response and
    finishes by logging out the user from CKAN.
    '''
    return toolkit.redirect_to(u'user.logout')


acs_endpoint = config.get('ckanext.saml2auth.acs_endpoint', '/acs')
saml2auth.add_url_rule(acs_endpoint, view_func=acs, methods=[u'GET', u'POST'])
saml2auth.add_url_rule(u'/user/saml2login', view_func=saml2login)
if not h.is_default_login_enabled():
    saml2auth.add_url_rule(
        u'/user/login', view_func=disable_default_login_register)
    saml2auth.add_url_rule(
        u'/user/register', view_func=disable_default_login_register)
saml2auth.add_url_rule(u'/slo', view_func=slo, methods=[u'GET', u'POST'])