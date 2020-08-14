Air::Lorcon2
================================================

![image of dragon]
(https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.cyberpunk.rs%2Fwireless-security-protocols-wep-wpa-wpa2-and-wpa3&psig=AOvVaw25-aASC0Cqn8SYh-pfoPnp&ust=1597525248767000&source=images&cd=vfe&ved=0CAIQjRxqFwoTCIDqt77Lm-sCFQAAAAAdAAAAABAD)

**REQUIREMENTS**

- [x] perl 
- [x] libpcap
- [x] flex
- [x] C compiler (gcc is fine)

**INSTALLATION**

for installing the *Air::Lorcon2* and *Lorcon2* libraries you just need to type:

```shell
   sudo make

```

this will start the Makefile outside the C and perl directories.

**CODE EXAMPLE**

for veryfing that everything works just type 
*perl -e '*

and write:

```perl

use Air::Lorcon2;
print Control_state();

```

if returns a value > 0 everything works fine.

**C DOCUMENTATION**
 
some articles about C Lorcon2 library are here:

  - https://github.com/kismetwireless/lorcon 
  - http://blog.opensecurityresearch.com/2012/09/getting-started-with-lorcon.html

**PERL DOCUMENTATION**

if interested in some examples for the perl library go under the examples/ directory.

**SPECIAL THANKS**

A big thanks to *andreas hadjiprocopis* aka Bliako, probably the best library contributor in the history, without him the biggest part related to C code wouldn't be working.

**other thanks**
* perlmonks community, especially syphilis  for his initial help
* *Mike Kershaw* aka Dragorn, the main developer of Lorcon2, who explained some obscure part of his code
* *GomoR*, the old version author, who never replied to my emails

**COPYRIGHT AND LICENCE**

Copyright (C) 2020 by *Edoardo Mantovani*, aka BASEBAND


This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


