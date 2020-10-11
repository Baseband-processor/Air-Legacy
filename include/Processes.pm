package Proc::Simple;
######################################################################
# Controlled by Edoardo Mantovani for Air::Lorcon2, 2020
# Copyright 1996-2001 by Michael Schilli, all rights reserved.
#
# This program is free software, you can redistribute it and/or 
# modify it under the same terms as Perl itself.
#
# The newest version of this module is available on
#     http://perlmeister.com/devel
# or on your favourite CPAN site under
#     CPAN/modules/by-author/id/MSCHILLI
#
######################################################################
 

use strict;
use POSIX;
use IO::Handle;
 
 
my $Debug = 0;
my $WNOHANG = get_system_nohang();
 
sub new { 
  my $proto = shift;
  my $class = ref($proto) || $proto;
 
  my $self  = {};
   
  # Init instance variables
  $self->{'kill_on_destroy'}   = undef;
  $self->{'signal_on_destroy'} = undef;
  $self->{'pid'}               = undef;
  $self->{'redirect_stdout'}   = undef;
  $self->{'redirect_stderr'}   = undef;
 
  bless($self, $class);
}

sub start {
  my $self  = shift;
  my ($func, @params) = @_;
 
  $SIG{'CHLD'} = \&THE_REAPER;
 
  $self->{'pid'} = fork();
  return 0 unless defined $self->{'pid'};  
 
  if($self->{pid} == 0) {
      POSIX::setsid();
      $self->dprt("setsid called ($$)");
 
      if (defined $self->{'redirect_stderr'}) {
        $self->dprt("STDERR -> $self->{'redirect_stderr'}");
        open(STDERR, ">", $self->{'redirect_stderr'}) ;
        autoflush STDERR 1 ;
      }
 
      if (defined $self->{'redirect_stdout'}) {
        $self->dprt("STDOUT -> $self->{'redirect_stdout'}");
        open(STDOUT, ">", $self->{'redirect_stdout'}) ;
        autoflush STDOUT 1 ;
      }
 
      if(ref($func) eq "CODE") {
          $self->dprt("Launching code");
          $func->(@params); exit 0;         
      } else {
          $self->dprt("Launching $func @params");
          exec $func, @params;      
          exit 0;                   
      }
  } elsif($self->{'pid'} > 0) {      # Parent:
      $INTERVAL{$self->{'pid'}}{'t0'} = time();
      $self->dprt("START($self->{'pid'})");
      # Register PID
      $EXIT_STATUS{$self->{'pid'}} = undef;
      $INTERVAL{$self->{'pid'}}{'t1'} = undef;
      return 1;                      
  } else {      
      return 0;                   
  }
}
 
sub poll {
  my $self = shift;
 
  $self->dprt("Polling");
 
  $self->THE_REAPER();
 
  if(defined($self->{pid})) {
      if(CORE::kill(0, $self->{pid})) {
          $self->dprt("POLL($self->{pid}) RESPONDING");
          return 1;
      } else {
          $self->dprt("POLL($self->{pid}) NOT RESPONDING");
      }
  } else {
     $self->dprt("POLL(NOT DEFINED)");
  }
 
  0;
}

sub kill { 
  my $self = shift;
  my $sig  = shift;
 
  # If no signal specified => SIGTERM-Signal
  $sig = POSIX::SIGTERM() unless defined $sig;
 
  # Use numeric signal if we get a string 
  if( $sig !~ /^[-\d]+$/ ) {
      $sig =~ s/^SIG//g;
      $sig = eval "POSIX::SIG${sig}()";
  }
 
  # Process initialized at all?
  if( !defined $self->{'pid'} ) {
      $self->dprt("No pid set");
      return 0;
  }
 
  if(CORE::kill($sig, $self->{'pid'})) {
      $self->dprt("KILL($sig, $self->{'pid'}) OK");
 
      CORE::kill(-$sig, $self->{'pid'});
  } else {
      $self->dprt("KILL($sig, $self->{'pid'}) failed ($!)");
      return 0;
  }
 
  1;
}
sub kill_on_destroy {
    my $self = shift;
    if (@_) { $self->{kill_on_destroy} = shift; }
    return $self->{kill_on_destroy};
}
 

sub signal_on_destroy {
    my $self = shift;
    if (@_) { $self->{signal_on_destroy} = shift; }
    return $self->{signal_on_destroy};
}

sub redirect_output {
 
  my $self = shift ;
  ($self->{'redirect_stdout'}, $self->{'redirect_stderr'}) = @_ ;
 
  1 ;
}
 

sub pid {
  my $self = shift;
  if (@_) { $self->{'pid'} = shift; }
  return $self->{'pid'};
}
 
sub t0 {
  my $self = shift;
 
  return $INTERVAL{$self->{'pid'}}{'t0'};
}
 

sub t1 {

  my $self = shift;
 
  return $INTERVAL{$self->{'pid'}}{'t1'};
}
 

sub DESTROY {
    my $self = shift;

    local( $., $@, $!, $^E, $? );
 

    return unless $self->pid();

    if ($self->kill_on_destroy) {
        $self->dprt("Kill on DESTROY");
        if (defined $self->signal_on_destroy) {
            $self->kill($self->signal_on_destroy);
        } else {
            $self->dprt("Sending KILL");
            $self->kill;
        }
    }
    delete $EXIT_STATUS{ $self->pid };
    if( $self->poll() ) {
        $DESTROYED{ $self->pid } = 1;
    }
}
 
sub exit_status{
        my( $self ) = @_;
        return $EXIT_STATUS{ $self->pid };
}
 

sub wait {
    my $self = shift;
 
    local $SIG{CHLD}; # disable until we're done
 
    my $pid = $self->pid();
 
 
    return $EXIT_STATUS{$pid} if defined $EXIT_STATUS{$pid};
 
    # all systems support FLAGS==0 (accg to: perldoc -f waitpid)
    my $res = waitpid $pid, 0;
    my $rc = $?;
 
    $INTERVAL{$pid}{'t1'} = time();
    $EXIT_STATUS{$pid} = $rc;
    dprt("", "For $pid, reaped '$res' with exit_status=$rc");
 
    return $rc;
}
 

sub THE_REAPER {
 
    local( $., $@, $!, $^E, $? );
 
    my $child;
    my $now = time();
 
    if(defined $WNOHANG) {

        foreach my $pid (keys %DESTROYED) {
            if(my $res = waitpid($pid, $WNOHANG) > 0) {
                # We reaped a zombie
                delete $DESTROYED{$pid};
                dprt("", "Reaped: $pid");
            }
        }
         
        foreach my $pid (keys %EXIT_STATUS) {
            dprt("", "Trying to reap $pid");
            if( defined $EXIT_STATUS{$pid} ) {
                dprt("", "exit status of $pid is defined - not reaping");
                next;
            }
            if(my $res = waitpid($pid, $WNOHANG) > 0) {
                # We reaped a truly running process
                $EXIT_STATUS{$pid} = $?;
                $INTERVAL{$pid}{'t1'} = $now;
                dprt("", "Reaped: $pid");
            } else {
                dprt("", "waitpid returned '$res'");
            }
        }
    } else { 

        dprt("", "reap everything for lack of WNOHANG");
        $child = CORE::wait();
        $EXIT_STATUS{$child} = $?;
        $INTERVAL{$child}{'t1'} = $now;
    }
 

}
 


sub debug { $Debug = shift; }

 
sub cleanup {
 
    for my $pid ( keys %INTERVAL ) {
        if( !exists $DESTROYED{ $pid } ) {
              # process has been reaped already, safe to delete 
              # its start/stop time
            delete $INTERVAL{ $pid };
        }
    }
}
 

sub dprt {
  my $self = shift;
  if($Debug) {
      require Time::HiRes;
      my ($seconds, $microseconds) = Time::HiRes::gettimeofday();
      print "[$seconds.$microseconds] ", ref($self), "> @_\n";
  }
}
 

sub get_system_nohang {

    my $nohang;
 
    open(SAVEERR, ">&STDERR");
 
       # If the system doesn't even know /dev/null, forget about it.
    open(STDERR, ">/dev/null") || return undef;

    close(STDERR);
 
       # Check for the constant
    eval 'use POSIX ":sys_wait_h"; $nohang = &WNOHANG;';
 
    open(STDERR, ">&SAVEERR");
    close(SAVEERR);
 
        # If there was an error, return undef
    return undef if $@;
 
    return $nohang;
}
 
1;
