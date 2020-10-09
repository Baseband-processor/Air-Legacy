# originally made by MANWAR, adapted by Edoardo Mantovani, 2020

package Term::ProgressBar;
 
use strict;
use warnings;
 
 
#XXX TODO Redo original test with count=20
#         Amount Output
#         Amount Prefix/Suffix
#         Tinker with $0?
#         Test use of last_update (with update(*undef*)) with scales
#         Choice of FH other than STDERR
#         If no term, output no progress bar; just progress so far
#         Use of simple term with v2.0 bar
#         If name is wider than term, trim name
#         Don't update progress bar on new?
 
 
use Carp                    qw( croak );
use Class::MethodMaker 1.02 qw( );
use Fatal                   qw( open sysopen close seek );
use POSIX                   qw( ceil strftime );
 
use constant MINUTE => 60;
use constant HOUR   => 60 * MINUTE;
use constant DAY    => 24 * HOUR;
 
# The point past which to give ETA of just date, rather than time
use constant ETA_DATE_CUTOFF => 3 * DAY;
# The point past which to give ETA of time, rather time left
use constant ETA_TIME_CUTOFF => 10 * MINUTE;
# The ratio prior to which to not dare any estimates
use constant PREDICT_RATIO => 0.01;
 
use constant DEFAULTS => {
                          lbrack     => '[',
                          rbrack     => ']',
                          minor_char => '*',
                          major_char => '=',
                          fh         => \*STDERR,
                          name       => undef,
                          ETA        => undef,
                          max_update_rate => 0.5,
 
                          # The following defaults are never used, but the keys
                          # are valuable for error checking
                          count      => undef,
                          bar_width  => undef,
                          term_width => undef,
                          term       => undef,
                          remove     => 0,
                          silent     => 0,
                         };
 
use constant ETA_TYPES => { map { $_ => 1 } qw( linear ) };
 
use constant ALREADY_FINISHED => 'progress bar already finished';
 
 
# This is here to allow testing to redirect away from the terminal but still
# see terminal output, IYSWIM
my $__FORCE_TERM = 0;
 
# ----------------------------------
# CLASS HIGHER-LEVEL FUNCTIONS
# ----------------------------------
 
# ----------------------------------
# CLASS HIGHER-LEVEL PROCEDURES
# ----------------------------------
 
sub __force_term {
  my $class = shift;
  ($__FORCE_TERM) = @_;
}
 
# ----------------------------------
# CLASS UTILITY FUNCTIONS
# ----------------------------------
 
sub term_size {
  my ( $self, $fh ) = @_;
  return if $self->silent;
 
  eval {
    require Term::ReadKey;
  }; if ($@) {
    warn "Guessing terminal width due to problem with Term::ReadKey\n";
    return 50;
  }
 
  my $result;
  eval {
    $result = (Term::ReadKey::GetTerminalSize($fh))[0];
    $result-- if ($^O eq "MSWin32" or $^O eq "cygwin");
  }; if ( $@ ) {
    warn "error from Term::ReadKey::GetTerminalSize(): $@";
  }
 
  # If GetTerminalSize() failed it should (according to its docs)
  # return an empty list.  It doesn't - that's why we have the eval {}
  # above - but also it may appear to succeed and return a width of
  # zero.
  #
  if ( ! $result ) {
    $result = 50;
    warn "guessing terminal width $result\n";
  }
 
  return $result;
}
 
# Don't document hash keys until tested that the give the desired affect!
 
 
Class::MethodMaker->import (new_with_init => 'new',
                            new_hash_init => 'hash_init',);
 
sub init {
  my $self = shift;
 
  # V1 Compatibility
  return $self->init({count      => $_[1], name => $_[0],
                      term_width => 50,    bar_width => 50,
                      major_char => '#',   minor_char => '',
                      lbrack     => '',    rbrack     => '',
                      term       => '0 but true',
                      silent     => 0,})
    if @_ == 2;
 
  my $target;
 
  croak
    sprintf("Term::ProgressBar::new We don't handle this many arguments: %d",
            scalar @_)
    if @_ != 1;
 
  my %config;
 
  if ( UNIVERSAL::isa ($_[0], 'HASH') ) {
    ($target) = @{$_[0]}{qw(count)};
    %config = %{$_[0]}; # Copy in, so later playing does not tinker externally
  } else {
    ($target) = @_;
  }
 
  if ( my @bad = grep ! exists DEFAULTS->{$_}, keys %config )  {
    croak sprintf("Input parameters (%s) to %s not recognized\n",
                  join(':', @bad), 'Term::ProgressBar::new');
  }
 
  croak "Target count required for Term::ProgressBar new\n"
    unless defined $target;
 
  $config{$_} = DEFAULTS->{$_}
    for grep ! exists $config{$_}, keys %{DEFAULTS()};
  delete $config{count};
 
  $config{term} = -t $config{fh}
    unless defined $config{term};
 
  if ( $__FORCE_TERM ) {
    $config{term} = 1;
    $config{term_width} = $__FORCE_TERM;
    die "term width $config{term_width} (from __force_term) too small"
      if $config{term_width} < 5;
  } elsif ( $config{term} and ! defined $config{term_width}) {
    $config{term_width} = $self->term_size($config{fh});
    die if $config{term_width} < 5;
  }
 
  unless ( defined $config{bar_width} ) {
    if ( defined $config{term_width} ) {
      # 5 for the % marker
      $config{bar_width}  = $config{term_width} - 5;
      $config{bar_width} -= $_
        for map(( defined $config{$_} ? length($config{$_}) : 0),
                  qw( lbrack rbrack name ));
      $config{bar_width} -= 2 # Extra for ': '
        if defined $config{name};
      $config{bar_width} -= 10
        if defined $config{ETA};
      if ( $config{bar_width} < 1 ) {
        warn "terminal width $config{term_width} too small for bar; defaulting to 10\n";
        $config{bar_width} = 10;
      }
#    } elsif ( ! $config{term} ) {
#      $config{bar_width}  = 1;
#      $config{term_width} = defined $config{ETA} ? 12 : 5;
    } else {
      $config{bar_width}  = $target;
      die "configured bar_width $config{bar_width} < 1"
      if $config{bar_width} < 1;
    }
  }
 
  $config{start} = time;
 
  select(((select $config{fh}), $| = 1)[0]);
 
  $self->ETA(delete $config{ETA});
 
  $self->hash_init (%config,
 
                    offset        => 0,
                    scale         => 1,
 
                    last_update   => 0,
                    last_position => 0,
                   );
  $self->target($target);
  $self->minor($config{term} && $target > $config{bar_width} ** 1.5);
 
  $self->update(0); # Initialize the progress bar
}
 
 
# ----------------------------------
# INSTANCE FINALIZATION
# ----------------------------------
 
# ----------------------------------
# INSTANCE COMPONENTS
# ----------------------------------
 
 
# Private Scalar Components
#  offset    ) Default: 0.       Added to any value supplied to update.
#  scale     ) Default: 1.       Any value supplied to update is multiplied by
#                                this.
#  major_char) Default: '='.     The character printed for the major scale.
#  minor_char) Default: '*'.     The character printed for the minor scale.
#  name      ) Default: undef.   The name to print to the side of the bar.
#  fh        ) Default: STDERR.  The filehandle to output progress to.
 
# Private Counter Components
#  last_update  ) Default: 0.    The so_far value last time update was invoked.
#  last_position) Default: 0.    The number of the last progress mark printed.
 
# Private Boolean Components
#  term      ) Default: detected (by C<Term::ReadKey>).
#              If unset, we assume that we are not connected to a terminal (or
#              at least, not a suitably intelligent one).  Then, we attempt
#              minimal functionality.
 
Class::MethodMaker->import
  (
   get_set       => [qw/ major_units major_char
                         minor_units minor_char
                         lbrack      rbrack
                         name
                         offset      scale
                         fh          start
                         max_update_rate
                         silent
                     /],
   counter       => [qw/ last_position last_update /],
   boolean       => [qw/ minor name_printed pb_ended remove /],
   # let it be boolean to handle 0 but true
   get_set       => [qw/ term /],
  );
 
# We generate these by hand since we want to check the values.
sub bar_width {
    my $self = shift;
    return $self->{bar_width} if not @_;
    croak 'wrong number of arguments' if @_ != 1;
    croak 'bar_width < 1' if $_[0] < 1;
    $self->{bar_width} = $_[0];
}
sub term_width {
    my $self = shift;
    return $self->{term_width} if not @_;
    croak 'wrong number of arguments' if @_ != 1;
    croak 'term_width must be at least 5' if $self->term and $_[0] < 5;
    $self->{term_width} = $_[0];
}
 
sub target {
  my $self = shift;
 
  if ( @_ ) {
    my ($target) = @_;
 
    if ( $target ) {
      $self->major_units($self->bar_width / $target);
      $self->minor_units($self->bar_width ** 2 / $target);
      $self->minor      ( defined $self->term_width   and
                          $self->term_width < $target );
    }
    $self->{target}  = $target;
  }
 
  return $self->{target};
}
 
sub ETA {
  my $self = shift;
  return if $self->silent;
  if (@_) {
    my ($type) = @_;
    croak "Invalid ETA type: $type\n"
      if defined $type and ! exists ETA_TYPES->{$type};
    $self->{ETA} = $type;
  }
 
  return $self->{ETA};
}
 
# ----------------------------------
# INSTANCE HIGHER-LEVEL FUNCTIONS
# ----------------------------------
 
# ----------------------------------
# INSTANCE HIGHER-LEVEL PROCEDURES
# ----------------------------------
 
 
sub no_minor {
  warn sprintf("%s: This method is deprecated.  Please use %s instead\n",
               (caller (0))[3], '$x->minor (0)',);
  $_[0]->clear_minor (0);
}
 
# -------------------------------------
 
 
sub update {
  my $self = shift;
  # returning target+1 as next value should avoid calling update
  # method in the smooth form of using the progress bar
  return $self->target+1 if $self->silent;
 
  my ($so_far) = @_;
 
  if ( ! defined $so_far ) {
    $so_far = $self->last_update + 1;
  }
 
  my $input_so_far = $so_far;
  $so_far *= $self->scale
    unless $self->scale == 1;
  $so_far += $self->offset;
 
  my $target = my $next = $self->target;
  my $name = $self->name;
  my $fh = $self->fh;
 
 
  if ( $target < 0 ) {
    if($input_so_far <= 0 or $input_so_far == $self->last_update) {
      print $fh "\r", ' ' x $self->term_width, "\r";
 
      if(defined $name) {
        if(!$self->remove or $input_so_far >= 0) {
          print $fh "$name...";
        }
                if(!$self->remove and $input_so_far < 0) {
                  print $fh "\n";
        }
      }
    }
    $self->last_update($input_so_far);
    return 2**32-1;
  } elsif ( $target == 0 ) {
    print $fh "\r";
    printf $fh "$name: "
      if defined $name;
    print $fh "(nothing to do)\n";
        return 2**32-1;
  }
 
  my $biggies     = $self->major_units * $so_far;
  my @chars = (' ') x $self->bar_width;
  $chars[$_] = $self->major_char
    for 0..$biggies-1;
 
  if ( $self->minor ) {
    my $smally      = $self->minor_units * $so_far % $self->bar_width;
    $chars[$smally] = $self->minor_char
      unless $so_far == $target;
    $next *= ($self->minor_units * $so_far + 1) / ($self->bar_width ** 2);
  } else {
    $next *= ($self->major_units * $so_far + 1) / $self->bar_width;
  }
 
  local $\ = undef;
 
  if ( $self->term > 0 ) {
    local $\ = undef;
    my $to_print = "\r";
    $to_print .= "$name: "
      if defined $name;
    my $ratio = $so_far / $target;
    # Rounds down %
    $to_print .= (sprintf ("%3d%% %s%s%s",
                        $ratio * 100,
                        $self->lbrack, join ('', @chars), $self->rbrack));
    my $ETA = $self->ETA;
    if ( defined $ETA and $ratio > 0 ) {
      if ( $ETA eq 'linear' ) {
        if ( $ratio == 1 ) {
          my $taken = time - $self->start;
          my $ss    = $taken % 60;
          my $mm    = int(($taken % 3600) / 60);
          my $hh    = int($taken / 3600);
          if ( $hh > 99 ) {
            $to_print .= sprintf('D %2dh%02dm', $hh, $mm, $ss);
          } else {
            $to_print .= sprintf('D%2dh%02dm%02ds', $hh, $mm, $ss);
          }
        } elsif ( $ratio < PREDICT_RATIO ) {
          # No safe prediction yet
          $to_print .= 'ETA ------';
        } else {
          my $time = time;
          my $left = (($time - $self->start) * ((1 - $ratio) / $ratio));
          if ( $left  < ETA_TIME_CUTOFF ) {
            $to_print .= sprintf '%1dm%02ds Left', int($left / 60), $left % 60;
          } else {
            my $eta  = $time + $left;
            my $format;
            if ( $left < DAY ) {
              $format = 'ETA  %H:%M';
            } elsif ( $left < ETA_DATE_CUTOFF ) {
              $format = sprintf('ETA %%l%%p+%d',$left/DAY);
            } else {
              $format = 'ETA %e%b';
            }
            $to_print .= strftime($format, localtime $eta);
          }
          # Calculate next to be at least SEC_PER_UPDATE seconds away
          if ( $left > 0 ) {
            my $incr = ($target - $so_far) / ($left / $self->max_update_rate);
            $next = $so_far + $incr
              if $so_far + $incr > $next;
          }
        }
      } else {
        croak "Bad ETA type: $ETA\n";
      }
    }
    for ($self->{last_printed}) {
        unless (defined and $_ eq $to_print) {
            print $fh $to_print;
        }
        $_ = $to_print;
    }
 
    $next -= $self->offset;
    $next /= $self->scale
      unless $self->scale == 1;
 
    if ( $so_far >= $target and $self->remove and ! $self->pb_ended) {
      print $fh "\r", ' ' x $self->term_width, "\r";
      $self->pb_ended;
    }
 
  } else {
    local $\ = undef;
 
    if ( $self->term ) { # special case for backwards compat.
     if ( $so_far == 0 and defined $name and ! $self->name_printed ) {
       print $fh "$name: ";
       $self->set_name_printed;
     }
 
      my $position = int($self->bar_width * ($input_so_far / $target));
      my $add      = $position - $self->last_position;
      $self->last_position_incr ($add)
        if $add;
 
     print $fh $self->major_char x $add;
 
     $next -= $self->offset;
     $next /= $self->scale
       unless $self->scale == 1;
    } else {
      my $pc = int(100*$input_so_far/$target);
      printf $fh "[%s] %s: %3d%%\n", scalar(localtime), ($name || ''), $pc;
 
      $next = ceil($target * ($pc+1)/100);
    }
 
    if ( $input_so_far >= $target ) {
      if ( $self->pb_ended ) {
        croak ALREADY_FINISHED;
      } else {
        if ( $self->term ) {
          print $fh "\n"
        }
        $self->set_pb_ended;
      }
    }
  }
 
 
  $next = $target if $next > $target;
 
  $self->last_update($input_so_far);
  return $next;
}
 
# -------------------------------------
 
 
sub message {
  my $self = shift;
  return if $self->silent;
  my ($string) = @_;
  chomp ($string);
 
  my $fh = $self->fh;
  local $\ = undef;
  if ( $self->term ) {
    print $fh "\r", ' ' x $self->term_width;
    print $fh "\r$string\n";
  } else {
    print $fh "\n$string\n";
    print $fh $self->major_char x $self->last_position;
  }
  undef $self->{last_printed};
  $self->update($self->last_update);
}
 
 
# ----------------------------------------------------------------------
  
1;
