Golle
=====

***libgolle*** is a library that allows individual nodes on a network to 
deal cards in a fully distributed way.

The algorithm was described by Phillipe Golle in his paper 
[Dealing Cards in Poker Games](http://crypto.stanford.edu/~pgolle/papers/poker.pdf). 
This library provides an implementation of the algorithm in order to 
develop distributed applications where nodes a randomly "dealt" 
distinct elements from a set.

------------------------------

###A note about copying

This library is released under the MIT software license (see `COPYING`). However, there is an *optional*
dependency on the GMP library, which is licensed under the GNU LGPL. The use of libgmp is not mandatory
(although we really recommend you use it), and you can turn it off by using `./configure --without-gmp`
if you want to avoid the burden of an LGPL-licensed library. However, this will leave you with only
long integer keys, which are insubstantial for cryptography.

Another option is to provide a big number library which is licensed in a way that suites you,
and to link it into the library using your own implementation of the libgolle number interface
(see `src/num.h`). You might need to hack the `configure.ac` file to get this to work.