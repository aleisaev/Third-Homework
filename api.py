#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import hashlib
import json
import logging
import re
import uuid
from collections import namedtuple, defaultdict
from copy import deepcopy
from functools import wraps
from http.server import BaseHTTPRequestHandler
from optparse import OptionParser
from weakref import WeakKeyDictionary

import scoring

SALT = "Otus"
AD_LOG = "admin"
AD_S = "42"
OK = 200
BAD_REQ = 400
FBD = 403
NOTF = 404
INV_REQ = 422
INT_ER = 500
ERRORS = {
    BAD_REQ: "Bad Request",
    FBD: "Forbidden",
    NOTF: "Not Found",
    INV_REQ: "Invalueid Request",
    INT_ER: "Internal Server Error",
}
UNK = 0
MA = 1
FEMA = 2
GENDERS = {
    UNK: "Unknown",
    MA: "Male",
    FEMA: "female",
}


class APIER(Exception):

    def __init__(self, message, *args, **kwargs):
        self.message = message
        super().__init__(*args, **kwargs)


class VALUEIER(APIER):
    pass


class FIELD:
    """Base class for all request FIELDs"""

    null_value = None
    _value = defaultdict(WeakKeyDictionary)
    _args = WeakKeyDictionary()

    arg = namedtuple('arg', ['requid', 'nullab'])

    def __init__(self, requid=False, nullab=False):
        self._args[self] = self.arg(requid, nullab)

    def __get__(self, instance, owner):
        return self._value[self].get(instance)

    def __set__(self, instance, value):
        # replace None value to special nullab value and exit
        if value is None:
            if self._args[self].requid:
                raise VALUEIER('FIELD is requid')
            else:
                self._value[self][instance] = value
                return
        if value == self.null_value:
            if self._args[self].nullab:
                self._value[self][instance] = value
                return
            else:
                raise VALUEIER('Fild is not nullab')
        self._value[self][instance] = self.DTV(value)

    def DTV(self, value):
        """Valueidation for specific data types"""
        raise NotImplementedError


class CFIELD(FIELD):
    null_value = ''

    def DTV(self, value):
        if not isinstance(value, str):
            raise VALUEIER('Must be string')
        return value


class IFIELD(FIELD):
    null_value = None

    def DTV(self, value):
        if not isinstance(value, int):
            raise VALUEIER('Must be integer')
        return value


class DFIELD(FIELD):
    null_value = {}

    def DTV(self, value):
        if not isinstance(value, dict):
            raise VALUEIER('Must be dict')
        return value


class LFIELD(FIELD):
    null_value = []

    def DTV(self, value):
        if not isinstance(value, list):
            raise VALUEIER('Must be list')
        return value


class DateFIELD(FIELD):
    null_value = None
    date_regex = re.compile(r'\d{2}\.\d{2}\.\d{4}')
    date_format = '%d.%m.%Y'

    def DTV(self, value):
        if value and not isinstance(value, str):
            raise VALUEIER('Date FIELD must be string')
        if value and not self.date_regex.match(value):
            raise VALUEIER('Wrong date format')
        return datetime.datetime.strptime(value, self.date_format)


class AFIELD(DFIELD):
    pass


class EFIELD(CFIELD):

    def DTV(self, value):
        value = super().DTV(value)
        if value.find('@') == -1:
            raise VALUEIER('Email not valueid')
        return value


class PFIELD(FIELD):
    null_value = ''

    def DTV(self, value):
        if isinstance(value, int):
            value = str(value)
        if not isinstance(value, str):
            raise VALUEIER('Phone must be string or integer')
        if value and (not value.startswith('7') or not len(value) == 11):
            raise VALUEIER('Not valueid phone number')
        return str(value)


class BDFIELD(DateFIELD):
    max_age = 70

    def DTV(self, value):
        value = super().DTV(value)
        if datetime.datetime.now().year - value.year > self.max_age:
            raise VALUEIER('Client is very old')
        return value


class GeFIELD(IFIELD):
    default_allow_values = [0, 1, 2]

    def __init__(self, *args, allowed_values=None, **kwargs):
        super().__init__(**kwargs)
        self.allow_values = self.default_allow_values
        if allowed_values:
            self.allow_values = allowed_values

    def DTV(self, value):
        value = super().DTV(value)
        if value not in self.allow_values:
            raise VALUEIER(f'Wrong value. Allowed {self.allow_values}')
        return value


class CLDFIELD(LFIELD):

    def DTV(self, value):
        value = super().DTV(value)
        for i in value:
            if not isinstance(i, int):
                raise VALUEIER('Must be list og integer')
        return value


class REQ_META(type):

    def __new__(cls, name, bases, attr_class):

        _FIELDs = {}
        for name, value in attr_class.items():
            if isinstance(value, FIELD):
                _FIELDs[name] = value

        attr_class['_FIELDs'] = _FIELDs

        return super().__new__(cls, name, bases, attr_class)


class Request(metaclass=REQ_META):
    """Base class for request forms"""

    def __init__(self, request):
        self._errors = {}
        self._request = deepcopy(request)
        self._is_Cleaning = False

    def Cleaning(self):
        for FIELD in self._FIELDs:
            try:
                setattr(self, FIELD, self._request.pop(FIELD, None))
            except VALUEIER as e:
                self._errors[FIELD] = e.message
        if self._request:
            self._errors['request'] = f'unexpected keyword arg [{list(self._request.keys())}]'
        self._is_Cleaning = True

    def FIELDs_errors(self):
        """Return map (FIELD_name: error_list)"""
        if not self._is_Cleaning:
            self.Cleaning()
        return self._errors

    def is_valueid(self):
        return not self.FIELDs_errors()

    def not_null_FIELDs(self):
        return [f for f in self._FIELDs if getattr(self, f) is not None]

    def get_context(self):
        return None


class CLINTERREQ(Request):
    client_ids = CLDFIELD(requid=True)
    date = DateFIELD(requid=False, nullab=True)

    def get_context(self):
        return len(self.client_ids)


class ONSCOREREQ(Request):
    first_name = CFIELD(requid=False, nullab=True)
    last_name = CFIELD(requid=False, nullab=True)
    email = EFIELD(requid=False, nullab=True)
    phone = PFIELD(requid=False, nullab=True)
    birthday = BDFIELD(requid=False, nullab=True)
    gender = GeFIELD(requid=False, nullab=True)

    def Cleaning(self):
        super().Cleaning()
        if not (self.phone and self.email) and not (self.first_name and self.last_name) and \
                not (self.gender is not None and self.birthday):
            self._errors['request'] = 'Not valueid request'

    def get_context(self):
        return self.not_null_FIELDs()


class METREQ(Request):
    account = CFIELD(requid=False, nullab=True)
    login = CFIELD(requid=True, nullab=True)
    token = CFIELD(requid=True, nullab=True)
    arg = AFIELD(requid=True, nullab=True)
    method = CFIELD(requid=True, nullab=False)

    @property
    def is_admin(self):
        return self.login == AD_LOG


class Method:
    """Methods management"""
    _methods = {}

    @classmethod
    def register(cls, method_name):
        """
        Register handler for method with name 'method_bame'
        Handler must implement interface:
            def method_handler_interface(mr: METREQ, ctx: dict, store):
                return response, code
        """

        def deco(func):
            @wraps(func)
            def wrap(*args, **kwargs):
                return func(*args, **kwargs)

            cls._methods[method_name] = wrap
            return wrap

        return deco

    @classmethod
    def Check_MET(cls, method_name):
        """Checking registered method with name 'method_name'"""
        return method_name in cls._methods

    @classmethod
    def get_handler(cls, method_name):
        return cls._methods.get(method_name)


@Method.register('online_score')
def online_score_handler(mr: METREQ, ctx: dict, store):
    if mr.is_admin:
        return {'score': 42}, OK

    arg = ONSCOREREQ(mr.arg)

    if not arg.is_valueid():
        return arg.FIELDs_errors(), INV_REQ

    score = scoring.Sget(store, arg.phone, arg.email, arg.birthday,
                              arg.gender, arg.first_name, arg.last_name)
    ctx['has'] = arg.get_context()

    return {'score': score}, OK


@Method.register('clients_interests')
def clients_interests_handler(mr: METREQ, ctx: dict, store):
    arg = CLINTERREQ(mr.arg)

    if not arg.is_valueid():
        return arg.FIELDs_errors(), INV_REQ

    ctx['nclients'] = arg.get_context()

    response = {}
    for i, client in enumerate(arg.client_ids):
        response[i + 1] = scoring.Iget(store, client)

    return response, OK


def check_auth(request):
    if request.is_admin:
        s = datetime.datetime.now().strftime("%Y%m%d%H") + AD_S
    else:
        s = request.account + request.login + SALT
    digest = hashlib.sha512(s.encode()).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    mr = METREQ(request['body'])

    if not mr.is_valueid():
        return mr.FIELDs_errors(), INV_REQ

    if not check_auth(mr):
        return ERRORS[FBD], FBD

    if not Method.Check_MET(mr.method):
        return {'method': ['Wrong method name']}, INV_REQ

    handler = Method.get_handler(mr.method)

    return handler(mr, ctx, store)


class MHHTPH(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQ
        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INT_ER
            else:
                code = NOTF

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "UNK Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode())
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MHHTPH)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
