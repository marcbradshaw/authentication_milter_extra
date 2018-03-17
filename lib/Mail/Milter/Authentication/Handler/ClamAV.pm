package Mail::Milter::Authentication::Handler::ClamAV;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
# VERSION
# ABSTRACT: Clam AV Scanner for Authentication Milter

use English qw{ -no_match_vars };
use Sys::Syslog qw{:standard :macros};
use ClamAV::Client;
use JSON;
use Mail::AuthenticationResults::Header::Entry;
use Mail::AuthenticationResults::Header::SubEntry;
use Mail::AuthenticationResults::Header::Comment;

use Data::Dumper;

sub default_config {
    return {
        'ca_name'        => '/var/run/clamav/clamd.ctl',
        'ca_host'        => '127.0.0.1',
        'ca_port'        => '3310',
        'hard_reject'    => 1,
    };
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows, $self->get_json( 'ClamAV_metrics' );
    return \@rows;
}

sub register_metrics {
    return {
        'clamav_total' => 'The number of emails processed for ClamAV',
    };
}

sub envfrom_callback {
    my ($self, $from) = @_;
    $self->{'lines'} = [];
    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    push @{$self->{'lines'}} ,$header . ': ' . $value . "\r\n";
    my $config = $self->handler_config();
    return;
}

sub eoh_callback {
    my ( $self ) = @_;
    push @{$self->{'lines'}} , "\r\n";
    return;
}

sub body_callback {
    my ( $self, $chunk ) = @_;
    push @{$self->{'lines'}} , $chunk;
    return;
}

sub eom_callback {
    my ($self) = @_;

    my $config = $self->handler_config();

    my %args;
    foreach my $param ( qw{ name host port } ) {
        $args{ 'socket_' . $param } = $config->{ 'socket_' . $param } if $config->{ 'socket_' . $param };
    }

    my $scanner = ClamAV::Client->new( %args );

    if ( ! $scanner ) {
        $self->log_error( 'ClamAVError: No Scanner' );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'x-virus' )->safe_set_value( 'temperror' );
        $self->add_auth_header( $header );
        $self->metric_count( 'clamav_total', { 'result' => 'noscanner' } );
        return;
    }

    if ( ! $scanner->ping() ) {
        $self->log_error( 'ClamAVError: Scanner Ping Failed' );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'x-virus' )->safe_set_value( 'temperror' );
        $self->add_auth_header( $header );
        $self->metric_count( 'clamav_total', { 'result' => 'scannerpingfail' } );
        return;
    }

    my $message = join( q{} , @{$self->{'lines'} } );
    my $result = $scanner->scan_scalar( \$message );

    if ( $result ) {
        $self->dbgout( 'ClamAV: Virus Found', $result, LOG_INFO );
        $self->metric_count( 'clamav_total', { 'result' => 'fail' } );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'x-virus' )->safe_set_value( 'fail' );
        $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( $result ) );
        $self->add_auth_header($header);
        if ( $config->{'hard_reject'} ) {
            if ( ( ! $self->is_local_ip_address() ) && ( ! $self->is_trusted_ip_address() ) ) {
                $self->reject_mail( '550 5.7.0 Virus policy violation' );
                $self->dbgout( 'ClamAVReject', "Policy reject", LOG_INFO );
            }
        }
    }
    else {
        $self->metric_count( 'clamav_total', { 'result' => 'pass' } );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'x-virus' )->safe_set_value( 'pass' );
        $self->add_auth_header($header);
    }

    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'lines'};
    return;
}

1;

__END__


=head1 DESCRIPTION

Virus check email for using clamav.

=head1 CONFIGURATION

        "ClamAV" : {
            "hard_reject"    : "1",
            "ca_name"        : "/var/run/clamav/clamd.ctl",
            "ca_host"        : "127.0.0.1",
            "ca_port"        : "3310"
        },

=head2 CONFIG

Add a block to the handlers section of your config as follows.

        "ClamAV" : {
            "hard_reject"    : "1",
            "ca_name"        : "/var/run/clamav/clamd.ctl",
            "ca_host"        : "127.0.0.1",
            "ca_port"        : "3310"
        },

