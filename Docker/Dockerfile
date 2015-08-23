# DOCKER-VERSION 0.3.4
FROM        marcbradshaw/authentication_milter:latest
MAINTAINER  Marc Bradshaw <marc@marcbradshaw.net>

# Install required libraries
RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update && \
    apt-get install -y \
        libdb-dev

# Install perl modules
RUN perlbrew exec cpanm \
        Mail::Milter::Authentication::Extra

# Cleanup
RUN perlbrew clean && \
    apt-get clean

CMD [ "/perl5/perlbrew/perls/perl-5.20.0/bin/perl", "/opt/startup.pl" ]

