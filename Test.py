import datetime
import functools
import hashlib
import unittest

import api


def cases(cases):
    def DECOR(f):
        @functools.wraps(f)
        def wrap(*args):
            for c in cases:
                new_args = args + (c if isinstance(c, tuple) else (c,))
                f(*new_args)

        return wrap

    return DECOR


class SUITEST(unittest.TestCase):
    def setUp(self):
        self.context = {}
        self.headers = {}
        self.settings = {}

    def get_response(self, request):
        return api.method_handler({"body": request, "headers": self.headers}, self.context, self.settings)

    def set_valueid_auth(self, request):
        if request.get("login") == api.AD_LOG:
            s = datetime.datetime.now().strftime("%Y%m%d%H") + api.AD_S
            request["token"] = hashlib.sha512(s.encode()).hexdigest()
        else:
            msg = request.get("account", "") + request.get("login", "") + api.SALT
            request["token"] = hashlib.sha512(msg.encode()).hexdigest()

    def test_empty_request(self):
        _, code = self.get_response({})
        self.assertEqual(api.INV_REQ, code)

    @cases([
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "", "arg": {}},
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "sdd", "arg": {}},
        {"account": "horns&hoofs", "login": "admin", "method": "online_score", "token": "", "arg": {}},
    ])
    def test_bad_auth(self, request):
        _, code = self.get_response(request)
        self.assertEqual(api.FBD, code)

    @cases([
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score"},
        {"account": "horns&hoofs", "login": "h&f", "arg": {}},
        {"account": "horns&hoofs", "method": "online_score", "arg": {}},
    ])
    def test_invalueid_method_request(self, request):
        self.set_valueid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.INV_REQ, code)
        self.assertTrue(len(response))

    @cases([
        {},
        {"phone": "79175002040"},
        {"phone": "89175002040", "email": "stupnikov@otus.ru"},
        {"phone": "79175002040", "email": "stupnikovotus.ru"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": -1},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": "1"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.03.1895"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "XXX"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.11.2007", "first_name": 1},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.10.2007",
         "first_name": "s", "last_name": 2},
        {"phone": "79175002040", "birthday": "01.01.2000", "first_name": "s"},
        {"email": "stupnikov@otus.ru", "gender": 1, "last_name": 2},
    ])
    def test_invalueid_score_request(self, arg):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arg": arg}
        self.set_valueid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.INV_REQ, code, arg)
        self.assertTrue(len(response))

    @cases([
        {"phone": "79175002040", "email": "stupnikov@otus.ru"},
        {"phone": 79175002040, "email": "stupnikov@otus.ru"},
        {"gender": 1, "birthday": "01.01.2000", "first_name": "a", "last_name": "b"},
        {"gender": 0, "birthday": "01.01.2000"},
        {"gender": 2, "birthday": "01.01.2000"},
        {"first_name": "a", "last_name": "b"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000",
         "first_name": "a", "last_name": "b"},
    ])
    def test_ok_score_request(self, arg):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arg": arg}
        self.set_valueid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.OK, code, arg)
        score = response.get("score")
        self.assertTrue(isinstance(score, (int, float)) and score >= 0, arg)
        self.assertEqual(sorted(self.context["has"]), sorted(arg.keys()))

    def test_ok_score_admin_request(self):
        arg = {"phone": "79175002040", "email": "stupnikov@otus.ru"}
        request = {"account": "horns&hoofs", "login": "admin", "method": "online_score", "arg": arg}
        self.set_valueid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.OK, code)
        score = response.get("score")
        self.assertEqual(score, 42)

    @cases([
        {},
        {"date": "20.07.2017"},
        {"client_ids": [], "date": "20.07.2017"},
        {"client_ids": {1: 2}, "date": "20.07.2017"},
        {"client_ids": ["1", "2"], "date": "20.07.2017"},
        {"client_ids": [1, 2], "date": "XXX"},
    ])
    def test_invalueid_interests_request(self, arg):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests", "arg": arg}
        self.set_valueid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.INV_REQ, code, arg)
        self.assertTrue(len(response))

    @cases([
        {"client_ids": [1, 2, 3], "date": datetime.datetime.today().strftime("%d.%m.%Y")},
        {"client_ids": [1, 2], "date": "19.07.2017"},
        {"client_ids": [0]},
    ])
    def test_ok_interests_request(self, arg):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests", "arg": arg}
        self.set_valueid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.OK, code, arg)
        self.assertEqual(len(arg["client_ids"]), len(response))
        self.assertTrue(all(v and isinstance(v, list) and all(isinstance(i, str) for i in v)
                            for v in response.values()))
        self.assertEqual(self.context.get("nclients"), len(arg["client_ids"]))


if __name__ == "__main__":
    unittest.main()
