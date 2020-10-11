package Proc::Simple;
######################################################################
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
 
Show 93 lines of Pod
 
require 5.003;
use strict;
use vars qw($VERSION %EXIT_STATUS %INTERVAL
            %DESTROYED);
 
use POSIX;
use IO::Handle;
 
$VERSION = '1.32';
 
######################################################################
# Globals: Debug and the mysterious waitpid nohang constant.
######################################################################
my $Debug = 0;
my $WNOHANG = get_system_nohang();
 
######################################################################
 
Show 19 lines of Pod
 
######################################################################
# $proc_obj=Proc::Simple->new(); - Constructor
######################################################################
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
 
######################################################################
 
Show 58 lines of Pod
 
######################################################################
# $ret = $proc_obj->start("prg"); - Launch process
######################################################################
sub start {
  my $self  = shift;
  my ($func, @params) = @_;
 
  # Reap Zombies automatically
  $SIG{'CHLD'} = \&THE_REAPER;
 
  # Fork a child process
  $self->{'pid'} = fork();
  return 0 unless defined $self->{'pid'};  #   return Error if fork failed
 
  if($self->{pid} == 0) { # Child
        # Mark it as process group leader, so that we can kill
        # the process group later. Note that there's a race condition
        # here because there's a window in time (while you're reading
        # this comment) between child startup and its new process group 
        # id being defined. This means that killpg() to the child during 
        # this time frame will fail. Proc::Simple's kill() method deals l
        # with it, see comments there.
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
          $func->(@params); exit 0;            # Start perl subroutine
      } else {
          $self->dprt("Launching $func @params");
          exec $func, @params;       # Start shell process
          exit 0;                    # In case something goes wrong
      }
  } elsif($self->{'pid'} > 0) {      # Parent:
      $INTERVAL{$self->{'pid'}}{'t0'} = time();
      $self->dprt("START($self->{'pid'})");
      # Register PID
      $EXIT_STATUS{$self->{'pid'}} = undef;
      $INTERVAL{$self->{'pid'}}{'t1'} = undef;
      return 1;                      #   return OK
  } else {      
      return 0;                      #   this shouldn't occur
  }
}
 
######################################################################
 
Show 9 lines of Pod
 
######################################################################
# $ret = $proc_obj->poll(); - Check process status
#                             1="running" 0="not running"
######################################################################
sub poll {
  my $self = shift;
 
  $self->dprt("Polling");
 
  # There's some weirdness going on with the signal handler. 
  # It runs into timing problems, so let's have poll() call
  # the REAPER every time to make sure we're getting rid of 
  # defuncts.
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
 
######################################################################
 
Show 15 lines of Pod
 
######################################################################
# $ret = $proc_obj->kill([SIGXXX]); - Send signal to process
#                                     Default-Signal: SIGTERM
######################################################################
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
 
  # Send signal
  if(CORE::kill($sig, $self->{'pid'})) {
      $self->dprt("KILL($sig, $self->{'pid'}) OK");
 
      # now kill process group of process to make sure that shell
      # processes containing shell characters, which get launched via
      # "sh -c" are killed along with their launching shells.
      # This might fail because of the race condition explained in 
      # start(), so we ignore the outcome.
      CORE::kill(-$sig, $self->{'pid'});
  } else {
      $self->dprt("KILL($sig, $self->{'pid'}) failed ($!)");
      return 0;
  }
 
  1;
}
 
######################################################################
 
Show 12 lines of Pod
 
######################################################################
# Method to set the kill_on_destroy flag
######################################################################
sub kill_on_destroy {
    my $self = shift;
    if (@_) { $self->{kill_on_destroy} = shift; }
    return $self->{kill_on_destroy};
}
 
######################################################################
 
Show 10 lines of Pod
 
######################################################################
# Send a signal on destroy
# undef means send the default signal (SIGTERM)
######################################################################
sub signal_on_destroy {
    my $self = shift;
    if (@_) { $self->{signal_on_destroy} = shift; }
    return $self->{signal_on_destroy};
}
 
######################################################################
 
Show 17 lines of Pod
 
######################################################################
sub redirect_output {
######################################################################
 
  my $self = shift ;
  ($self->{'redirect_stdout'}, $self->{'redirect_stderr'}) = @_ ;
 
  1 ;
}
 
######################################################################
 
Show 8 lines of Pod
 
######################################################################
sub pid {
######################################################################
  my $self = shift;
 
  # Allow the pid to be set - assume this is only
  # done internally so don't document this behaviour in the
  # pod.
  if (@_) { $self->{'pid'} = shift; }
  return $self->{'pid'};
}
 
######################################################################
 
Show 8 lines of Pod
 
######################################################################
sub t0 {
######################################################################
  my $self = shift;
 
  return $INTERVAL{$self->{'pid'}}{'t0'};
}
 
######################################################################
 
Show 8 lines of Pod
 
######################################################################
sub t1 {
######################################################################
  my $self = shift;
 
  return $INTERVAL{$self->{'pid'}}{'t1'};
}
 
Show 9 lines of Pod
 
######################################################################
# Destroy method
# This is run automatically on undef
# Should probably not bother if a poll shows that the process is not
# running.
######################################################################
sub DESTROY {
    my $self = shift;
 
    # Localize special variables so that the exit status from waitpid
    # doesn't leak out, causing exit status to be incorrect.
    local( $., $@, $!, $^E, $? );
 
    # Processes never started don't have to be cleaned up in
    # any special way.
    return unless $self->pid();
 
    # If the kill_on_destroy flag is true then
    # We need to send a signal to the process
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
 
######################################################################
 
Show 6 lines of Pod
 
######################################################################
# returns the exit status of the child process, undef if the child
# hasn't yet exited
######################################################################
sub exit_status{
        my( $self ) = @_;
        return $EXIT_STATUS{ $self->pid };
}
 
######################################################################
 
Show 9 lines of Pod
 
######################################################################
# waits until the child process terminates and then
# returns the exit status of the child process.
######################################################################
sub wait {
    my $self = shift;
 
    local $SIG{CHLD}; # disable until we're done
 
    my $pid = $self->pid();
 
    # test if the signal handler reap'd this pid some time earlier or even just
    # a split second before localizing $SIG{CHLD} above; also kickout if
    # they've wait'd or waitpid'd on this pid before ...
 
    return $EXIT_STATUS{$pid} if defined $EXIT_STATUS{$pid};
 
    # all systems support FLAGS==0 (accg to: perldoc -f waitpid)
    my $res = waitpid $pid, 0;
    my $rc = $?;
 
    $INTERVAL{$pid}{'t1'} = time();
    $EXIT_STATUS{$pid} = $rc;
    dprt("", "For $pid, reaped '$res' with exit_status=$rc");
 
    return $rc;
}
 
######################################################################
# Reaps processes, uses the magic WNOHANG constant
######################################################################
sub THE_REAPER {
 
    # Localize special variables so that the exit status from waitpid
    # doesn't leak out, causing exit status to be incorrect.
    local( $., $@, $!, $^E, $? );
 
    my $child;
    my $now = time();
 
    if(defined $WNOHANG) {
        # Try to reap every process we've ever started and 
        # whichs Proc::Simple object hasn't been destroyed.
        #
        # This is getting really ugly. But if we just call the REAPER
        # for every SIG{CHLD} event, code like this will fail:
        #
        # use Proc::Simple;
        # $proc = Proc::Simple->new(); $proc->start(\&func); sleep(5);
        # sub func { open(PIPE, "/bin/ls |"); @a = <PIPE>; sleep(1); 
        #            close(PIPE) or die "PIPE failed"; }
        # 
        # Reason: close() doesn't like it if the spawn has
        # been reaped already. Oh well.
        #
 
        # First, check if we can reap the processes which 
        # went out of business because their kill_on_destroy
        # flag was set and their objects were destroyed.
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
        # If we don't have $WNOHANG, we don't have a choice anyway.
        # Just reap everything.
        dprt("", "reap everything for lack of WNOHANG");
        $child = CORE::wait();
        $EXIT_STATUS{$child} = $?;
        $INTERVAL{$child}{'t1'} = $now;
    }
 
    # Don't reset signal handler for crappy sysV systems. Screw them.
    # This caused problems with Irix 6.2
    # $SIG{'CHLD'} = \&THE_REAPER;
}
 
######################################################################
 
Show 6 lines of Pod
 
# Proc::Simple::debug($level) - Turn debug on/off
sub debug { $Debug = shift; }
 
######################################################################
 
Show 9 lines of Pod
 
sub cleanup {
 
    for my $pid ( keys %INTERVAL ) {
        if( !exists $DESTROYED{ $pid } ) {
              # process has been reaped already, safe to delete 
              # its start/stop time
            delete $INTERVAL{ $pid };
        }
    }
}
 
######################################################################
# Internal debug print function
######################################################################
sub dprt {
  my $self = shift;
  if($Debug) {
      require Time::HiRes;
      my ($seconds, $microseconds) = Time::HiRes::gettimeofday();
      print "[$seconds.$microseconds] ", ref($self), "> @_\n";
  }
}
 
######################################################################
sub get_system_nohang {
######################################################################
# This is for getting the WNOHANG constant of the system -- but since
# the waitpid(-1, &WNOHANG) isn't supported on all Unix systems, and
# we still want Proc::Simple to run on every system, we have to 
# quietly perform some tests to figure out if -- or if not.
# The function returns the constant, or undef if it's not available.
######################################################################
    my $nohang;
 
    open(SAVEERR, ">&STDERR");
 
       # If the system doesn't even know /dev/null, forget about it.
    open(STDERR, ">/dev/null") || return undef;
       # Close stderr, since some weirdo POSIX modules write nasty
       # error messages
    close(STDERR);
 
       # Check for the constant
    eval 'use POSIX ":sys_wait_h"; $nohang = &WNOHANG;';
 
       # Re-open STDERR
    open(STDERR, ">&SAVEERR");
    close(SAVEERR);
 
        # If there was an error, return undef
    return undef if $@;
 
    return $nohang;
}
 
1;
