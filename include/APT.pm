package Linux::APT;
 
use strict;
use warnings;
 
sub new
{
  my $class = shift;
  my $self = {};
  my %args = @_;
 
  $self->{debug} = $args{debug};
 
  $self->{aptget} = $args{aptget} || `which apt-get`;
  chomp($self->{aptget});
  die qq(apt-get doesn't appear to be available.\n) unless $self->{aptget};
 
  $self->{aptcache} = $args{aptcache} || `which apt-cache`;
  chomp($self->{aptcache});
  die qq(apt-cache doesn't appear to be available.\n) unless $self->{aptcache};
 
  return bless($self, $class);
}
  
sub update
{
  my $self = shift;
  my $update = {};
 
  if (open(APT, "$self->{aptget} -q update 2>&1 |"))
  {
    while (my $line = <APT>)
    {
      chomp($line);
      print qq($line\n) if $self->{debug};
      if ($line =~ m#Fetched (\d+\S+) in (.*?) \((\d+\S+?)\)#i)
      {
        $update->{size} = $1;
        $update->{time} = $2;
        $update->{speed} = $3;
      }
      elsif ($line =~ s#^W: ##) # warning
      {
        my $warning = {};
        $warning->{message} = $line;
        push(@{$update->{warning}}, $warning);
      }
      elsif ($line =~ s#^E: ##) # error
      {
        my $error = {};
        $error->{message} = $line;
        push(@{$update->{error}}, $error);
      }
    }
    close(APT);
  }
  else
  {
    die "Couldn't use APT: $!\n";
  }
 
  return $update;
}
  
sub toupgrade
{
  my $self = shift;
  my $updates = {};
 
  if (open(APT, "echo n | $self->{aptget} -q -V upgrade 2>&1 |"))
  {
    while (my $line = <APT>)
    {
      chomp($line);
      print qq($line\n) if $self->{debug};
      if ($line =~ m#^\s+(\S+)\s+\((\S+)\s+=>\s+(\S+)\)#)
      {
        my $update = {};
        my $package = $1;
        $update->{current} = $2;
        $update->{new} = $3;
        $updates->{packages}->{$package} = $update;
      }
      elsif ($line =~ s#^W: ##) # warning
      {
        my $warning = {};
        $warning->{message} = $line;
        push(@{$updates->{warning}}, $warning);
      }
      elsif ($line =~ s#^E: ##) # error
      {
        my $error = {};
        $error->{message} = $line;
        push(@{$updates->{error}}, $error);
      }
    }
    close(APT);
  }
 
  return $updates;
}
  
sub search
{
  my $self = shift;
  my $search = {};
  my @args = @_;
  my $opts = {
    in => ['all'],
  };
 
  if (ref($args[0]) eq 'HASH')
  {
    my $optarg = shift;
    foreach my $arg (keys(%{$optarg}))
    {
      $opts->{$arg} = $optarg->{$arg};
    }
  }
 
  foreach my $pkg (@args) 
  {
    if (open(APT, "$self->{'aptcache'} search '$pkg' 2>&1 |")) 
    {
      while (my $line = <APT>) 
      {
        my $okay = 0;
        $okay = 1 if (grep(m/all/, @{$opts->{in}}));
        chomp($line);
        print qq($line\n) if $self->{'debug'};
        if ($line =~ m/^(\S+)\s+-\s+(.*)$/) 
        {
          my ($name, $desc) = ($1, $2);
          chomp($desc);
          $okay = 1 if (grep(m/name/, @{$opts->{in}}) && $name =~ m/$pkg/i);
          $okay = 1 if (grep(m/description/, @{$opts->{in}}) && $desc =~ m/$pkg/i);
          next unless $okay;
          $search->{$pkg}->{$name} = $desc;
        }
      }
    }
    close(APT);
  }
 
  return $search;
}
  
sub install
{
  my $self = shift;
  my @install = @_;
 
  my $action = 'install';
  my $force = '';
  my $noop = 0;
  my $packages = '';
  my $installed = {};
 
  foreach my $install (@install)
  {
    if ($install eq '-force')
    {
      $force = '--force-yes';
      next;
    }
    elsif ($install eq '-test')
    {
      $noop = 1;
      next;
    }
    elsif ($install eq '-remove')
    {
      $action = 'remove';
      next;
    }
    elsif ($install eq '-purge')
    {
      $action = 'purge';
      next;
    }
 
    (my $package = $install) =~ s/[^a-z0-9\+\-_\.]//ig;
    $packages .= $package.' ';
  }
 
  my $state = '';
  my $notreally = ($noop ? 'echo n |' : '');
  my $justsayyes = ($noop ? '-s' : "-y $force");
 
  if (open(APT, "$notreally $self->{aptget} $justsayyes -q -V $action $packages 2>&1 |"))
  {
    while (my $line = <APT>)
    {
      chomp($line);
      print qq($line\n) if $self->{debug};
      if ($line =~ m/The following packages will be REMOVED:/i)
      {
        $state = 'removed';
      }
      elsif ($line =~ m/The following NEW packages will be installed:/i)
      {
        $state = 'installed';
      }
      elsif ($line =~ m/The following packages will be upgraded:/i)
      {
        $state = 'upgraded';
      }
      elsif ($line =~ m#^\s+(\S+)\s+\((\S+)\s+=>\s+(\S+)\)#) # upgrading
      {
        my $update = {};
        my $package = $1;
        $update->{old} = $2;
        $update->{new} = $3;
        $package =~ s/\*$//;
        $installed->{packages}->{$package} = $update;
        $installed->{$state}->{$package} = $installed->{packages}->{$package};
      }
      elsif ($line =~ m#^\s+(\S+)\s+\((\S+)\)#) # installing
      {
        my $update = {};
        my $package = $1;
        my $version = $2;
        $package =~ s/\*$//;
        if ($state eq 'removed')
        {
          $installed->{$state}->{$package} = $version
        }
        else
        {
          $update->{new} = $version;
          $installed->{packages}->{$package} = $update if $state;
          $installed->{$state}->{$package} = $installed->{packages}->{$package} if $state;
        }
      }
      elsif ($line =~ m/^(\d+)\s+upgraded,\s+(\d+)\s+newly\s+installed,\s+(\d+)\s+to\s+remove\s+and\s+(\d+)\s+not\s+upgraded./i)
      {
        $state = '';
        $installed->{intended}->{upgraded} = $1;
        $installed->{intended}->{installed} = $2;
        $installed->{intended}->{removed} = $3;
        $installed->{intended}->{upgradable} = $4;
      }
      elsif ($line =~ s#^W: ##) # warning
      {
        my $warning = {};
        $warning->{message} = $line;
        push(@{$installed->{warning}}, $warning);
      }
      elsif ($line =~ s#^E: ##) # error
      {
        my $error = {};
        $error->{message} = $line;
        push(@{$installed->{error}}, $error);
      }
    }
    close(APT);
  }
 
  unless ($noop)
  {
    foreach my $package (keys(%{$installed->{packages}}))
    {
      if (open(APT, "$self->{aptcache} showpkg $package |"))
      {
        while (my $line = <APT>)
        {
          chomp($line);
          print qq($line\n) if $self->{debug};
          if ($line =~ m#^(\S+)\s+.*?\(/var/lib/dpkg/status\)#)
          {
            $installed->{packages}->{$package}->{current} = $1;
          }
        }
        close(APT);
      }
    }
  }
 
  return $installed;
}
 
 
sub remove
{
  my $self = shift;
  return $self->install('-remove', @_);
}
 
sub purge
{
  my $self = shift;
  return $self->install('-purge', @_);
}
  
1;
