package Mail::Milter::Authentication::Extra;
use strict;
use warnings;
use version; our $VERSION = version->declare('v0.1.0');


1;

__END__

=head1 NAME

Mail::Milter::Authentication::Extra - A PERL Mail Authentication Milter

=head1 DESCRIPTION

A PERL implemtation of email authentication standards rolled up into a single easy to use milter.

=head1 SYNOPSIS

Subclass of Net::Server::PreFork for bringing up the main server process for authentication_milter.

Please see Net::Server docs for more detail of the server code.


=head1 DEPENDENCIES

  Mail::Milter::Authentication
  Mail::SpamAssassin
  Mail::SpamAssassin::Client
  DB_File

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2015

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.
