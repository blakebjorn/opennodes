"""
Automatic documentation generator for Flask

Modified from https://github.com/acoomans/flask-autodoc
Copyright (c) 2013 Arnaud Coomans
Copyright (c) 2018 Opennodes / Blake Bjorn Anderson

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
import inspect
import json
import os
import re
import sys
from collections import defaultdict
from operator import attrgetter
from typing import Callable, Optional, Any, Dict
from flask import current_app, render_template, render_template_string
from flask.app import Flask
from jinja2 import evalcontextfilter

try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack

if sys.version < '3':
    get_function_code = attrgetter('func_code')
else:
    get_function_code = attrgetter('__code__')


class Autodoc(object):
    def __init__(self, app: Optional[Flask] = None) -> None:
        self.app = app
        self.func_groups = defaultdict(set)
        self.func_locations = defaultdict(dict)
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        if hasattr(app, 'teardown_appcontext'):
            app.teardown_appcontext(self.teardown)
        else:
            app.teardown_request(self.teardown)
        self.add_custom_template_filters(app)

    def teardown(self, exception: None) -> None:
        ctx = stack.top

    def add_custom_template_filters(self, app: Flask) -> None:
        """Add custom filters to jinja2 templating engine"""
        self.add_custom_nl2br_filters(app)

    def add_custom_nl2br_filters(self, app: Flask) -> None:
        """Add a custom filter nl2br to jinja2
         Replaces all newline to <BR>
        """
        _paragraph_re = re.compile(r'(?:\r\n|\r|\n){3,}')

        @app.template_filter()
        @evalcontextfilter
        def nl2br(eval_ctx, value):
            result = '\n\n'.join('%s' % p.replace('\n', '<br>\n')
                                 for p in _paragraph_re.split(value))
            return result

    def doc(self, groups: None = None) -> Callable:
        """Add flask route to autodoc for automatic documentation

        Any route decorated with this method will be added to the list of
        routes to be documented by the generate() or html() methods.

        By default, the route is added to the 'all' group.
        By specifying group or groups argument, the route can be added to one
        or multiple other groups as well, besides the 'all' group.
        """

        def decorator(f):
            # Set group[s]
            if type(groups) is list:
                groupset = set(groups)
            else:
                groupset = set()
                if type(groups) is str:
                    groupset.add(groups)
            groupset.add('all')
            self.func_groups[f] = groupset

            # Set location
            caller_frame = inspect.stack()[1]
            self.func_locations[f] = {
                'filename': caller_frame[1],
                'line': caller_frame[2],
            }

            return f

        return decorator

    def deconstruct_docstring(self, docstring):
        docstring = str(docstring)

        params = re.findall("(\:param )(.*?\: )(.*)", docstring)
        returns = re.findall("(\:return: )(.*)", docstring)

        if params:
            docstring = docstring.split("".join(params[0]))[0].strip()
        elif returns:
            docstring = docstring.split("".join(returns[0]))[0].strip()
        return docstring, params, returns

    def generate(self, groups='all', sort=None):
        """Return a list of dict describing the routes specified by the
        doc() method

        Each dict contains:
         - methods: the set of allowed methods (ie ['GET', 'POST'])
         - rule: relative url (ie '/user/<int:id>')
         - endpoint: function name (ie 'show_user')
         - doc: docstring of the function
         - args: function arguments
         - defaults: defaults values for the arguments

        By specifying the group or groups arguments, only routes belonging to
        those groups will be returned.

        Routes are sorted alphabetically based on the rule.
        """
        groups_to_generate = list()
        if type(groups) is list:
            groups_to_generate = groups
        elif type(groups) is str:
            groups_to_generate.append(groups)

        links = []
        for rule in current_app.url_map.iter_rules():
            if rule.endpoint == 'static':
                continue
            func = current_app.view_functions[rule.endpoint]
            func_groups = self.func_groups[func]
            location = self.func_locations.get(func, None)

            if func_groups.intersection(groups_to_generate):
                docstring, arguments, returns = self.deconstruct_docstring(func.__doc__)

                if isinstance(arguments, set):
                    arguments = list(arguments)
                arguments = arguments if len(arguments) >= 1 and arguments[0] != "None" else None
                links.append(
                    dict(
                        methods=sorted([x for x in rule.methods if x not in ("HEAD", "OPTIONS")]),
                        rule="%s" % rule,
                        endpoint=rule.endpoint,
                        docstring=docstring,
                        args=arguments,
                        defaults=rule.defaults,
                        location=location,
                        returns=returns
                    )
                )
        if sort:
            return sort(links)
        else:
            return sorted(links, key=lambda x: x['rule'].lower())

    def html(self, groups='all', template=None, **context):
        """Return an html string of the routes specified by the doc() method

        A template can be specified. A list of routes is available under the
        'autodoc' value (refer to the documentation for the generate() for a
        description of available values). If no template is specified, a
        default template is used.

        By specifying the group or groups arguments, only routes belonging to
        those groups will be returned.
        """
        if template:
            return render_template(template,
                                   autodoc=self.generate(groups=groups),
                                   **context)
        else:
            filename = os.path.join(
                os.path.dirname(__file__),
                'templates',
                'docs.html'
            )
            with open(filename) as file:
                content = file.read()
                with current_app.app_context():
                    return render_template_string(
                        content,
                        autodoc=self.generate(groups=groups),
                        **context)
