#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import re

form ="""
<html>
<head>
    <title> Signup</title>
    <style>
        .label{text-align:right;
        }
        .error{color:red;
        }
    </style>
</head>
<body>
<h1>Signup</h1>
<form method = "post">
    <table>
        <tr>
            <td class="label">
                Username
            </td>
            <td>
                <input type = "text" name="username" value =%(username)s>
                <span class ="error">%(username_error)s %(user_valid_error)s</span>
            </td>
        </tr>
        <tr>
            <td class ="label">
                Password
            </td>
            <td>
                <input type = "password" name="password">
                <span class ="error">%(password_error)s</span>
            </td>
        </tr>
        <tr>
            <td class="label">
                Verify Password
            </td>
            <td>
                <input type = "password" name ="verify">
                <span class ="error">%(verify_password)s</span>
            </td>
        </tr>
        <tr>
            <td class="label">
                Email (optional)
            </td>
            <td>
                <input type = "text" name = "email">
                <span class ="error">%(email_error)s</span>
            </td>
        </tr>
    </table>
    <input type = "submit">
    </form>
</body>
</html>

    """

class MainHandler(webapp2.RequestHandler):
    def write_form(self, username="", password="", verify="", email="", username_error="", user_valid_error="", password_error="", verify_password="", email_error=""):
        self.response.out.write(form % {"username": username,
                                        "password": password,
                                        "verify": verify,
                                        "email": email,
                                        "username_error": username_error,
                                        "user_valid_error": user_valid_error,
                                        "password_error": password_error,
                                        "verify_password": verify_password,
                                        "email_error": email_error})

    def get(self):
        self.write_form()


    def post(self):
        new_user = self.request.get("username")
        user_password = self.request.get("password")
        verify_password = self.request.get("verify")
        user_email = self.request.get("email")


        username_error=""
        user_valid_error=""
        password_error=""
        verify_error=""
        email_error=""

        error=False


        #no username entered
        if new_user == "":
            username_error ="You must enter a username"
            error=True

        #invalid username
        name = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        if not name.match(new_user):
            user_valid_error = "That is not a valid username"
            error=True

        #no password entered
        if user_password == "":
            password_error="You must enter a vaild password"
            error=True

        #verify password
        if not user_password == verify_password:
            verify_error="Your passwords don't match"
            error=True

        # #verify email
        if user_email:
            pass

            mail = re.compile(r"^[\S]+@[\S]+.[\S]+$")
            if not mail.match(user_email):
                email_error="That's not a valid email"
                error=True

        clean_username=cgi.escape(new_user, quote=True)
        clean_password=cgi.escape("user_password", quote=True)
        clean_verify=cgi.escape("verify_password", quote=True)
        clean_email=cgi.escape(user_email, quote=True)

        if error==True:
            self.write_form(clean_username, clean_password, clean_verify, clean_email, username_error, user_valid_error, password_error, verify_error, email_error)
        else:
            self.redirect("/welcome?username=%s" % new_user)

class Welcome(webapp2.RequestHandler):
    def get(self):
        username = self.request.get("username")
        response = "Welcome, " + username
        self.response.write(response)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/welcome', Welcome)
], debug=True)
