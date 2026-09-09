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

from saml2.ident import code, decode
from saml2.saml import NameID

log = logging.getLogger(__name__)


def _make_serializable(obj):
    """Recursively convert non-JSON-serializable pysaml2 objects to plain
    types so Flask can serialize the session to JSON.
    """
    if isinstance(obj, NameID):
        # Canonical string encoding provided by pysaml2 itself
        return code(obj)
    if isinstance(obj, dict):
        return {k: _make_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_make_serializable(i) for i in obj]
    if not isinstance(obj, (str, int, float, bool, type(None))):
        try:
            return str(obj)
        except Exception:
            return None
    return obj


def _deserialize_name_id(value):
    """Accept every possible stored format and always return a NameID object.

    Handles:
    - NameID objects (already restored)
    - dicts in the older '__type__': 'NameID' format
    - strings encoded with pysaml2's code() function
    - bare strings (treated as the NameID text)
    """
    if isinstance(value, NameID):
        return value

    if isinstance(value, dict) and value.get('__type__') == 'NameID':
        name_id = NameID()
        name_id.text = value.get('text')
        name_id.format = value.get('format')
        name_id.name_qualifier = value.get('name_qualifier')
        name_id.sp_name_qualifier = value.get('sp_name_qualifier')
        return name_id

    if isinstance(value, str):
        try:
            # A code()-encoded string looks like:
            # "0=name_qualifier,1=sp_name_qualifier,2=format,4=text"
            name_id = decode(value)
            if isinstance(name_id, NameID):
                return name_id
        except Exception:
            pass
        # Fall back: bare string, treat it as the NameID text
        name_id = NameID()
        name_id.text = value
        return name_id

    return value


def _restore_name_id(obj):
    """Recursively walk the stored structure. Only used for dict/list
    traversal; name_id itself is handled explicitly by the callers.
    """
    if isinstance(obj, dict):
        if obj.get('__type__') == 'NameID':
            return _deserialize_name_id(obj)
        return {k: _restore_name_id(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_restore_name_id(i) for i in obj]
    return obj


def set_subject_id(session, subject_id):
    if isinstance(subject_id, NameID):
        session['_saml2_subject_id'] = code(subject_id)
    else:
        session['_saml2_subject_id'] = subject_id


def get_subject_id(session):
    """Return the NameID for the current SAML session.

    IMPORTANT: prefer the name_id stored inside _saml_session_info so
    that the subject_id used by global_logout() is guaranteed to be
    IDENTICAL to the name_id used by add_information_about_person().
    If they differ in any attribute (e.g. name qualifiers), pysaml2's
    cache lookup fails with a KeyError during SLO.
    """
    info = get_saml_session_info(session)
    if isinstance(info, dict):
        name_id = info.get('name_id')
        if isinstance(name_id, NameID):
            return name_id

    # Fallback: the separately stored subject id
    try:
        return _deserialize_name_id(session['_saml2_subject_id'])
    except KeyError:
        return None


def set_saml_session_info(session, saml_session_info):
    info = dict(saml_session_info)
    name_id = info.get('name_id')
    if isinstance(name_id, NameID):
        # Use pysaml2's own canonical string encoding for name_id
        info['name_id'] = code(name_id)
    session['_saml_session_info'] = _make_serializable(info)


def get_saml_session_info(session):
    try:
        raw = session['_saml_session_info']
    except KeyError:
        return None

    info = _restore_name_id(raw)

    # Whatever format name_id was stored in, always return a NameID object
    if isinstance(info, dict) and 'name_id' in info:
        info['name_id'] = _deserialize_name_id(info['name_id'])

    return info