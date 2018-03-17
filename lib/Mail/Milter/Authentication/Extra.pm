package Mail::Milter::Authentication::Extra;
use strict;
use warnings;
use Mail::Milter::Authentication 2;
# VERSION
# ABSTRACT: Extra handlers for Authentication Milter

1;

__END__

=head1 DESCRIPTION

Additional handlers for Authentication Milter which did not fit within the core functionality, or
are not yet 100% production ready.

=head1 SYNOPSIS

This is a collection of additional handler modules for Authentication Milter.

Please see the output of 'authentication_milter --help' for usage help.

=head1 DEPENDENCIES

  Mail::Milter::Authentication
  Mail::SpamAssassin
  Mail::SpamAssassin::Client
  DB_File

