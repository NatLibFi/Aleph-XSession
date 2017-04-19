# User authentication and session management module for Aleph ILS X-service API
#
# Copyright (C) 2017 University Of Helsinki (The National Library Of Finland)
#
# This file is part of aleph-xsession
#
# aleph-xsession program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# aleph-xsession is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# @licend  The above is the entire license notice
# for the JavaScript code in this file.

package Aleph::XSession;

use 5.008000;
use strict;
use warnings;
use LWP::UserAgent;
use HTTP::Request::Common;
use strict;
use Fcntl; 
use CGI qw(:standard);

sub new {
    my $invocant = shift;
    my $class = ref($invocant) || $invocant;

    my $self = { config => $_[0] };

    #Check the configs

    if (!defined($self->{config}->{'x-server'})) { die("$0: Missing config attribute: 'x-server'"); }
    if (!defined($self->{config}->{'scratch_dir'})) { die("$0: Missing config attribute: 'scratch_dir'"); }
    if (!defined($self->{config}->{'session_duration'})) { die("$0: Missing config attribute: 'session_duration'"); }        
    if (!defined($self->{config}->{'user_library'})) { die("$0: Missing config attribute: 'user_library'"); }        

    return bless($self,$class);
}

sub getUser() {
    my $self = shift;
    return $self->{'user'};
}
sub getUserPass() {
    my $self = shift;
    return $self->{'password'};
}


sub getErrorMsg() {
    my $self = shift;
    return $self->{'errormsg'};
}

sub getConfig() {
    my $self = shift;
    return $self->{'config'};
}


sub start() {
    my $self = shift;
    my $config = $self->{'config'};
    
    
    if (!defined($_[0]) || !defined($_[1])) {
        return undef;
    }
    
    my ($user, $password) = @_;
    $self->{'user'} = $user;
    $self->{'password'} = $password;

    if ($user eq '' || $password eq '') {
        $self->{'errormsg'} = "Username or password is empty";
        return undef;
    }
    
    my $x_request = "$config->{'x-server'}?op=user-auth&library=$config->{'user_library'}&staff_user=" . url_encode($user) . '&staff_pass=' . url_encode($password);

    my $ua = LWP::UserAgent->new(
    	ssl_opts => { verify_hostname => 0},
    	timeout => 60, agent => 'Mozilla/4.0 (compatible; XSession perl module;)');
    my $request = HTTP::Request->new(GET => $x_request);
    my $response = $ua->request($request);
    if (!$response->is_success()) {
        $self->{'errormsg'} = "X-Server request $x_request failed: " . $response->code . ': ' . $response->message . ', content: ' . $response->content;
        return undef;
    }

    my $xml = $response->content;
    if ($xml =~ /<error>(.*)<\/error>/) {
    
    $self->{'errormsg'} = "Error: $1";
        return undef;
    }


    my ($success) = $xml =~ /<reply>(.*?)<\/reply>/s;

    return undef if ($success ne 'ok');

    my ($session) = $xml =~ /<session-id>(.*?)<\/session-id>/s;

    if (!$session) {
        $self->{'errormsg'} = 'Could not parse user-auth response';
        return undef;
    }
    $self->{'session'} = $session;
    
    $self->create_session_file();
    
    
    my $cgi = new CGI();
    my $cookie = $cgi->cookie(-name => 'X-session',
    -value => $session);

    $self->{'cookie'} = $cookie;
        
    return $self->{'cookie'};
}


sub load($) {

    my $self = shift;
        
    $self->{'session'} = cookie('X-session');
    
    my ($user,$pass) = $self->read_session_file();

    if (!defined($user) || !defined($pass)) {
        return undef;
    } else {
        $self->{'user'} = $user;
        $self->{'password'} = $pass;
    }
    
    return 1;
}

sub end() {
    my $self = shift;

    $self->delete_session_file();
    delete $self->{'session'};
}


sub delete_session_file()
{
    my $self = shift;
    my $config = $self->{'config'};
    
    my ($session) = $self->{'session'};

    return if (!$session);

    my $file = "$config->{'scratch_dir'}/session.$session";
    unlink($file);
}

sub delete_expired_session_files($)
{
    my $self = shift;
    my $config = $self->{'config'};

  my @files = glob($config->{'scratch_dir'} . '/session.*');

  foreach my $file (@files)
  {
    my ($dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat($file);
    unlink($file) if ($mtime < time() - $config->{'session_duration'});
  }
}

sub read_session_file($)
{
    my $self = shift;
    
    my $config = $self->{'config'};
    my $session = $self->{'session'};

  $self->delete_expired_session_files();

    if (!defined($session)) {
        return (undef, undef);
    }
    
  my $fh;
  my $file = "$config->{'scratch_dir'}/session.$session";
  open($fh, "<$file") || return (undef, undef);
  my $user = <$fh>;
  my $password = <$fh>;
  close($fh);

  utime(undef, undef, $file);

  chop($user);
  chop($password);

  return ($user, $password);
}


sub create_session_file()
{
    my $self = shift;
    my $config = $self->{'config'};


  my ($session, $user, $password) = ($self->{'session'} ,$self->{'user'}, $self->{'password'});

  my $fh;
  my $file = "$config->{'scratch_dir'}/session.$session";
  sysopen($fh, $file, O_WRONLY|O_CREAT, 0600) || die("Could not create session file: $!");
  print $fh "$user\n";
  print $fh "$password\n";
  close($fh);
}

sub url_encode($)
{
  my ($str) = @_;

  $str =~ s/([^A-Za-z0-9\-])/sprintf("%%%02X", ord($1))/seg;
  $str =~ s/%20/\+/g;
  return $str;
}

sub xml_decode($)
{
  my ($str) = @_;

  $str =~ s/&amp;/&/g;
  $str =~ s/&lt;/</g;
  $str =~ s/&gt;/>/g;
  $str =~ s/&apos;/'/g;
  $str =~ s/&quot;/"/g;

  return $str;
}

sub xml_encode($)
{
  my ($str) = @_;

  $str =~ s/&/&amp;/g;
  $str =~ s/</&lt;/g;
  $str =~ s/>/&gt;/g;
  $str =~ s/'/&apos;/g;
  $str =~ s/"/&quot;/g;

  return $str;
}

1;
__END__

=head1 NAME

Aleph::XSession - Perl extension for authenticating users at Aleph X-server and managing sessions.

=head1 SYNOPSIS

  use Aleph::XSession;
    
    %attrs = ( 
    #url of the X-server.
        'x-server' => 'http://libtest.csc.fi:8991/X', 
    
    # Location where session files are saved. Note that the session files contain username & password so it should be secure place.
        'scratch_dir' => '/tmp',  
    
    # Session duration (in seconds). After this the cookie expires and the session files older than this are deleted from server.
        'session_duration' => 600, 

    # X-server library url parameter. Should point to the schema where users are stored in oracle.    
        'user_library' => 'USR00'   
    );
    
    $XSession = new Aleph::XSession(\%attrs);    
    Creates a session with given attributes.
  
    $XSession->start($username,$password);
  Returns CGI::Cookie if succesful, otherwise undef (give the cookie to the user).
    
    $XSession->load();
  Loads session from X-session cookie. Returns true if session is valid, otherwise undef.
    
    $XSession->getUser();
  Returns the username of the user.
  
    $XSession->getUserPass();
  Returns the password of the user.
  
    $XSession->getErrorMsg();
  If you get undef from calling a function, check the getErrorMsg() for more info.
    
    $XSession->end();
  Terminates the session.



=head1 DESCRIPTION

Note scripts using this module must also use CGI::Cookie
Requires:

use LWP::UserAgent;
use HTTP::Request::Common;
use strict;
use Fcntl; 
use CGI qw(:standard);


=head2 EXPORT

None.



=head1 SEE ALSO


=head1 AUTHOR

The University Of Helsinki (The National Library of Finland)

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2017 University Of Helsinki (The National Library Of Finland)

This file is part of aleph-xsession

aleph-xsession program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

aleph-xsession is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

=cut
