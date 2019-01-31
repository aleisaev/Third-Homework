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
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class ApiError(Exception):

    def __init__(self, message, *args, **kwargs):
        self.message = message
        super().__init__(*args, **kwargs)


class ValidationError(ApiError):
    pass


class Field:
    """Base class for all request fields"""

    null_value = None
    _value = defaultdict(WeakKeyDictionary)
    _args = WeakKeyDictionary()

    arguments = namedtuple('arguments', ['required', 'nullable'])

    def __init__(self, required=False, nullable=False):
        self._args[self] = self.arguments(required, nullable)

    def __get__(self, instance, owner):
        return self._value[self].get(instance)

    def __set__(self, instance, value):
        # replace None value to special nullable value and exit
        if value is None:
            if self._args[self].required:
                raise ValidationError('Field is required')
            else:
                self._value[self][instance] = value
                return
        if value == self.null_value:
            if self._args[self].nullable:
                self._value[self][instance] = value
                return
            else:
                raise ValidationError('Fild is not nullable')
        self._value[self][instance] = self.data_type_validate(value)

    def data_type_validate(self, value):
        """Validation for specific data types"""
        raise NotImplementedError


class CharField(Field):
    null_value = ''

    def data_type_validate(self, value):
        if not isinstance(value, str):
            raise ValidationError('Must be string')
        return value


class IntegerField(Field):
    null_value = None

    def data_type_validate(self, value):
        if not isinstance(value, int):
            raise ValidationError('Must be integer')
        return value


class DictField(Field):
    null_value = {}

    def data_type_validate(self, value):
        if not isinstance(value, dict):
            raise ValidationError('Must be dict')
        return value


class ListField(Field):
    null_value = []

    def data_type_validate(self, value):
        if not isinstance(value, list):
            raise ValidationError('Must be list')
        return value


class DateField(Field):
    null_value = None
    date_regex = re.compile(r'\d{2}\.\d{2}\.\d{4}')
    date_format = '%d.%m.%Y'

    def data_type_validate(self, value):
        if value and not isinstance(value, str):
            raise ValidationError('Date field must be string')
        if value and not self.date_regex.match(value):
            raise ValidationError('Wrong date format')
        return datetime.datetime.strptime(value, self.date_format)


class ArgumentsField(DictField):
    pass


class EmailField(CharField):

    def data_type_validate(self, value):
        value = super().data_type_validate(value)
        if value.find('@') == -1:
            raise ValidationError('Email not valid')
        return value


class PhoneField(Field):
    null_value = ''

    def data_type_validate(self, value):
        if isinstance(value, int):
            value = str(value)
        if not isinstance(value, str):
            raise ValidationError('Phone must be string or integer')
        if value and (not value.startswith('7') or not len(value) == 11):
            raise ValidationError('Not valid phone number')
        return str(value)


class BirthDayField(DateField):
    max_age = 70

    def data_type_validate(self, value):
        value = super().data_type_validate(value)
        if datetime.datetime.now().year - value.year > self.max_age:
            raise ValidationError('Client is very old')
        return value


class GenderField(IntegerField):
    default_allow_values = [0, 1, 2]

    def __init__(self, *args, allowed_values=None, **kwargs):
        super().__init__(**kwargs)
        self.allow_values = self.default_allow_values
        if allowed_values:
            self.allow_values = allowed_values

    def data_type_validate(self, value):
        value = super().data_type_validate(value)
        if value not in self.allow_values:
            raise ValidationError(f'Wrong value. Allowed {self.allow_values}')
        return value


class ClientIDsField(ListField):

    def data_type_validate(self, value):
        value = super().data_type_validate(value)
        for i in value:
            if not isinstance(i, int):
                raise ValidationError('Must be list og integer')
        return value


class RequestMeta(type):

    def __new__(cls, name, bases, attr_class):

        _fields = {}
        for name, value in attr_class.items():
            if isinstance(value, Field):
                _fields[name] = value

        attr_class['_fields'] = _fields

        return super().__new__(cls, name, bases, attr_class)


class Request(metaclass=RequestMeta):
    """Base class for request forms"""

    def __init__(self, request):
        self._errors = {}
        self._request = deepcopy(request)
        self._is_clean = False

    def clean(self):
        for field in self._fields:
            try:
                setattr(self, field, self._request.pop(field, None))
            except ValidationError as e:
                self._errors[field] = e.message
        if self._request:
            self._errors['request'] = f'unexpected keyword arguments [{list(self._request.keys())}]'
        self._is_clean = True

    def fields_errors(self):
        """Return map (field_name: error_list)"""
        if not self._is_clean:
            self.clean()
        return self._errors

    def is_valid(self):
        return not self.fields_errors()

    def not_null_fields(self):
        return [f for f in self._fields if getattr(self, f) is not None]

    def get_context(self):
        return None


class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def get_context(self):
        return len(self.client_ids)


class OnlineScoreRequest(Request):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def clean(self):
        super().clean()
        if not (self.phone and self.email) and not (self.first_name and self.last_name) and \
                not (self.gender is not None and self.birthday):
            self._errors['request'] = 'Not valid request'

    def get_context(self):
        return self.not_null_fields()


class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


class Method:
    """Methods management"""
    _methods = {}

    @classmethod
    def register(cls, method_name):
        """
        Register handler for method with name 'method_bame'
        Handler must implement interface:
            def method_handler_interface(mr: MethodRequest, ctx: dict, store):
                return response, code
        """

        def deco(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)

            cls._methods[method_name] = wrapper
            return wrapper

        return deco

    @classmethod
    def check_method(cls, method_name):
        """Checking registered method with name 'method_name'"""
        return method_name in cls._methods

    @classmethod
    def get_handler(cls, method_name):
        return cls._methods.get(method_name)


@Method.register('online_score')
def online_score_handler(mr: MethodRequest, ctx: dict, store):
    if mr.is_admin:
        return {'score': 42}, OK

    arguments = OnlineScoreRequest(mr.arguments)

    if not arguments.is_valid():
        return arguments.fields_errors(), INVALID_REQUEST

    score = scoring.get_score(store, arguments.phone, arguments.email, arguments.birthday,
                              arguments.gender, arguments.first_name, arguments.last_name)
    ctx['has'] = arguments.get_context()

    return {'score': score}, OK


@Method.register('clients_interests')
def clients_interests_handler(mr: MethodRequest, ctx: dict, store):
    arguments = ClientsInterestsRequest(mr.arguments)

    if not arguments.is_valid():
        return arguments.fields_errors(), INVALID_REQUEST

    ctx['nclients'] = arguments.get_context()

    response = {}
    for i, client in enumerate(arguments.client_ids):
        response[i + 1] = scoring.get_interests(store, client)

    return response, OK


def check_auth(request):
    if request.is_admin:
        s = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
    else:
        s = request.account + request.login + SALT
    digest = hashlib.sha512(s.encode()).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    mr = MethodRequest(request['body'])

    if not mr.is_valid():
        return mr.fields_errors(), INVALID_REQUEST

    if not check_auth(mr):
        return ERRORS[FORBIDDEN], FORBIDDEN

    if not Method.check_method(mr.method):
        return {'method': ['Wrong method name']}, INVALID_REQUEST

    handler = Method.get_handler(mr.method)

    return handler(mr, ctx, store)


class MainHTTPHandler(BaseHTTPRequestHandler):
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
            code = BAD_REQUEST
        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
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
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
