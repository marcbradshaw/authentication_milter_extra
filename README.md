Authentication Milter Extra
---------------------------

Extra handler modules for [Authentication Milter](https://github.com/fastmail/authentication_milter).
A PERL implemtation of email authentication standards rolled up into a single easy to use milter.

This repo provides the following additional modules.

- SpamAssassin - Runs mail through SpamAssassin
- UserDB map local emails to local users (used in SpamAssassin module)

UserDB map currently only supports a hash: style table.

These handlers are not considered production ready and may not be fully documented.

Installation
------------

You will first need to install and configure Authentication Milter and Spam Assassin

To install this module, run the following commands:

 - perl Makefile.PL
 - make
 - make test
 - make install

Config
------

Please see the output of 'authentication_milter --help SpamAssassin' and
'authentication_milter --help UserDB'

Credits and License
-------------------

Copyright (c) 2015 Marc Bradshaw. <marc@marcbradshaw.net>

This is free software; you can redistribute it and/or modify it under the
same terms as the Perl 5 programming language system itself.

See [LICENSE](LICENSE) file for license details.

Code Climate
------------

master branch [![Build Status](https://travis-ci.org/marcbradshaw/authentication_milter_extra.svg?branch=master)](https://travis-ci.org/marcbradshaw/authentication_milter_extra)

Contributing
------------

Please fork and send pull requests.

