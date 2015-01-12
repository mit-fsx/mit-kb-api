import errno
import logging
import os
import sys

from functools import wraps, partial

import flask
import jinja2

from oic.oauth2 import rndstr

from .config import APIConfig as config
from . import auth
from .models import ValidationError
from .database import db

logger = logging.getLogger('kb_api.admin')

admin_blueprint = flask.Blueprint('admin', __name__,
                                  template_folder='templates.admin')

class InternalError(Exception):
    pass

class FormDataError(InternalError):
    pass

class LoginError(InternalError):
    pass

def authenticated_route(f=None, require_admin=False, optional=False):
    if f is None:
        return partial(authenticated_route, require_admin=require_admin,
                       optional=optional)
    if require_admin and optional:
        raise TypeError('Cannot mix optional=True and require_admin=True')
    @wraps(f)
    def auth_decorator(*args, **kwargs):
        username = flask.session.get('remote_user', None)
        if username is None:
            return flask.redirect(flask.url_for('.login'))
        user = auth.RemoteUser(username=username)
        logger.info('user=%s', user)
        if not optional and not user.authenticated:
            logger.info("Unauthenticated user.")
            raise LoginError("This page requires authentication.")
        if require_admin and not user.is_administrator: 
            logger.info("User is not administrator.")
            raise LoginError("You must be an administrator to access this page.")
        kwargs['remote_user'] = user
        return f(*args, **kwargs)
    return auth_decorator

# TODO: Replace this with WTForms or something
def extract_formdata(f=None, required=tuple()):
    if f is None:
        return partial(extract_formdata, required=required)
    @wraps(f)
    def auth_decorator(*args, **kwargs):
        if flask.request.method == 'POST':
            kwargs['formdata'] = flask.request.form
            if not all([x in kwargs['formdata'] for x in required]):
                raise FormDataError("Some required form data was missing.")
        return f(*args, **kwargs)
    return auth_decorator

@admin_blueprint.app_errorhandler(500)
def admin_errorhandler(exception, **kwargs):
    if not isinstance(exception, InternalError):
        logger.exception(exception)
    else:
        # Don't print the traceback if it's an error we deliberately raised.
        logger.error(str(exception))
    return flask.render_template('error.html', exception=exception)

@admin_blueprint.app_template_filter('permlabel')
def _filter_permlabel(value):
    if not isinstance(value, basestring):
        raise ValueError('String required')
    return ' '.join([x[0].upper() + x[1:].lower() for x in value.split('_')])

@admin_blueprint.app_template_filter('datetime')
def _filter_datetime(value, fmt='long'):
    if fmt == 'shortdate':
        return value.strftime("%m/%d/%y")
    if fmt == 'short':
        return value.strftime("%m/%d/%y %H:%M:%S")
    if fmt == 'c':
        return value.ctime()
    return value.strftime("%Y-%m-%d %H:%M:%S")

def strip_string(s):
    s = s.strip()
    if len(s) > 0:
        return s
    raise ValueError

@admin_blueprint.route('/', methods=['GET'])
@authenticated_route(optional=True)
def enroll_user(remote_user=None, formdata={}, **kwargs):
    return flask.redirect(flask.url_for('.user_root'))

@admin_blueprint.route('/login', methods=['GET'])
def login(remote_user=None, **kwargs):
    oidc = auth.OIDC()
    flask.session['remote_user'] = None
    flask.session['state'] = rndstr()
    flask.session['nonce'] = rndstr()
    return flask.render_template('login.html',
                                 remote_user=remote_user,
                                 openid_url=oidc.get_login_uri(flask.session['state'], flask.session['nonce']))

@admin_blueprint.route('/openid', methods=['GET', 'POST'])
def openid_login(**kwargs):
    oidc = auth.OIDC()
    userinfo = oidc.process_request(flask.request.args,
                                    flask.session['state'],
                                    flask.session['nonce'])
    remote_user = auth.RemoteUser(username=userinfo['email'])
    if not remote_user.authenticated:
        auth.add_user(username=userinfo['email'],
                      email=userinfo['email'],
                      real_name=userinfo['name'],
                      is_admin=False)
    flask.session['remote_user'] = userinfo['email']
    return flask.redirect(flask.url_for('.user_root'))


@admin_blueprint.route('/admin/users', methods=['GET', 'POST'])
@authenticated_route(require_admin=True)
@extract_formdata(required=('users',))
def manage_users(remote_user=None, formdata={}, **kwargs):
    # TODO: move this to auth.something; check if we removed our own access
    if flask.request.method == 'POST':
        for username in formdata.getlist('users'):
            user = auth.lookup_user(username)
            if user is not None:
                admin = formdata.get('admin-{0}'.format(user.id), 'no') == 'yes'
                auth.update_db_object(user, {'is_admin': admin})
    users = auth.get_all_users()
    return flask.render_template('users.html',
                                 remote_user=remote_user,
                                 users=users)

@admin_blueprint.route('/admin/users/add', methods=['POST'])
@authenticated_route(require_admin=True)
@extract_formdata(required=('username', 'email', 'realname'))
def add_admin_user(remote_user=None, formdata={}, **kwargs):
    # TODO: move this to auth.something; check if we removed our own access
    user = auth.lookup_user(formdata['username'])
    if user is not None:
        auth.update_db_object(user, {'is_admin': True})
    else:
        auth.add_user(username=formdata['username'],
                      email=formdata['email'],
                      real_name=formdata['realname'],
                      is_admin=True)
    return flask.redirect(flask.url_for('.manage_users'))

@admin_blueprint.route('/admin', methods=['GET', 'POST'])
@authenticated_route(require_admin=True)
@extract_formdata(required=('owner', 'email', 'description'))
def admin_root(remote_user=None, formdata={}, **kwargs):
    if flask.request.method == 'POST':
        try:
            user = auth.lookup_user(formdata['owner'])
            if user is None:
                user = auth.add_user(username=formdata['owner'])
            auth.add_key(user,
                         email=formdata['email'],
                         description=formdata['description'],
                         auto_approve=True)
        except ValidationError as e:
            kwargs['formdata'] = formdata
            kwargs['form_error'] = e.message
    keys = auth.get_all_keys()
    return flask.render_template('index.html',
                                 title='API Keys',
                                 is_admin=True,
                                 remote_user=remote_user,
                                 all_keys=[k for k in keys if k.status != auth.Statuses.PENDING],
                                 pending_keys=[k for k in keys if k.status == auth.Statuses.PENDING],
                                 **kwargs)

@admin_blueprint.route('/admin/approve', methods=['POST'])
@authenticated_route(require_admin=True)
@extract_formdata(required=('key_id',))
def approve_key(remote_user=None, formdata={}, **kwargs):
    key = auth.lookup_key(formdata['key_id'])
    if key is None:
        raise InternalError("Key with id '{0}' not found while approving".format(formdata['key_id']))
    if key.status != auth.Statuses.PENDING:
        raise InternalError("Key with id '{0}' not pending".format(formdata['key_id']))
    auth.update_db_object(key,
                          {'status': auth.Statuses.ACTIVE})
    return flask.redirect(flask.url_for('.admin_root'))

@admin_blueprint.route('/admin/edit', methods=['POST'])
@authenticated_route(require_admin=True)
@extract_formdata(required=('key_id',))
def admin_edit_key(remote_user=None, formdata={}, **kwargs):
    key = auth.lookup_key(formdata['key_id'])
    if key is None:
        raise InternalError("Key with id '{0}' not found while editing".format(formdata['key_id']))
    tmplargs = {'remote_user': remote_user}
    tmplargs['key'] = key
    tmplargs['permissions'] = auth.Permissions
    tmplargs['statuses'] = auth.Statuses.all
    tmplargs['is_admin'] = remote_user.is_administrator
    if formdata.get('edit_key_submit', None) is not None:
        update_vals = formdata.to_dict()
        tmplargs['formdata'] = formdata
        try:
            if formdata['status'] not in auth.Statuses:
                raise ValidationError('status', 'invalid status')
            update_vals['status'] = getattr(auth.Statuses,
                                            formdata['status'])
            update_vals['owner'] = auth.lookup_user(formdata['owner'])
            if update_vals['owner'] is None:
                raise ValidationError('owner', 'owner is missing')
            auth.update_db_object(key,
                                  update_vals,
                                  fields=('description', 'email', 'owner', 'status'))
            for space_key in formdata.getlist('permissions', type=strip_string):
                perms = map(lambda x: getattr(auth.Permissions, x), formdata.getlist('permissions.{0}'.format(space_key)))
                key.set_permission(space_key, *perms)
            if len(formdata['_new_permissions_space'].strip()):
                perms = map(lambda x: getattr(auth.Permissions, x), formdata.getlist('_new_permissions'))
                key.set_permission(formdata['_new_permissions_space'], *perms)
            db.session.commit()
            # return flask.redirect(flask.url_for('admin_root'))
        except KeyError as e:
            tmplargs['form_error'] = 'Some form values were missing: {0}'.format(e)
        except ValidationError as e:
            tmplargs['form_error'] = e
    return flask.render_template('edit_key.html', **tmplargs);

@admin_blueprint.route('/edit', methods=['POST'])
@authenticated_route
@extract_formdata(required=('key_id',))
def edit_key(remote_user=None, formdata={}, **kwargs):
    key = auth.lookup_key(formdata['key_id'])
    if key is None:
        raise InternalError("Key with id '{0}' not found while editing".format(key_id))
    tmplargs = {'remote_user': remote_user}
    tmplargs['key'] = key
    tmplargs['permissions'] = auth.Permissions
    tmplargs['statuses'] = auth.Statuses.all
    tmplargs['is_admin'] = False
    tmplargs['deactivatable'] = key.status == auth.Statuses.ACTIVE
    if key.owner != remote_user.user:
        raise InternalError("Not authorized to edit key '{0}'".format(formdata['key_id']))
    if key.status not in (auth.Statuses.ACTIVE, auth.Statuses.INACTIVE):
        raise InternalError("That key is not editable.")
    if formdata.get('edit_key_submit', None) is not None:
        update_vals = formdata.to_dict()
        if formdata.get('deactivate', 'no') == 'yes':
            update_vals['status'] = auth.Statuses.INACTIVE
        else:
            update_vals['status'] = key.status
        auth.update_db_object(key,
                              update_vals,
                              fields=('description', 'email', 'status'))
        return flask.redirect(flask.url_for('.user_root'))
    return flask.render_template('edit_key.html', **tmplargs);


@admin_blueprint.route('/user', methods=['GET', 'POST'])
@authenticated_route
@extract_formdata(required=('email', 'description'))
def user_root(remote_user=None, formdata={}, **kwargs):
    tmplargs={'is_admin': False}
    keys = remote_user.user.keys
    if flask.request.method == 'POST':
        tmplargs['formdata'] = formdata
        pending = len(filter(lambda x: x.status == auth.Statuses.PENDING,
                             keys))
        if pending >= 2:
            tmplargs['form_error'] = "You have 2 pending keys.  Please wait until they are approved before requesting more."
        else:
            try:
                auth.add_key(remote_user.user,
                             email=formdata['email'],
                             description=formdata['description'],
                             auto_approve=True)
                del tmplargs['formdata']
            except ValidationError as e:
                tmplargs['field_error'] = e.field
                tmplargs['form_error'] = e
    # Sort in descending order by mod date
    tmplargs['all_keys'] = sorted(keys, key=lambda x: x.modified, reverse=True)
    tmplargs['remote_user'] = remote_user
    return flask.render_template('request.html', **tmplargs)

