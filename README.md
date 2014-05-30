Golle
=====

**libgolle** is a library that allows individual nodes on a network to 
deal cards in a fully distributed way.

The algorithm was described by Phillipe Golle in his paper 
[Dealing Cards in Poker Games](http://crypto.stanford.edu/~pgolle/papers/poker.pdf). 
This library provides an implementation of the algorithm in order to 
develop distributed applications where nodes a randomly "dealt" 
distinct elements from a set.

------------------------------

###Building

To build, you'll need a _recent_ copy of OpenSLL's development package (header files, libraries etc.) and the autotools suite including libtoolize, autoheader, aclocal, autoconf, and automake. Bootstrap and build the whole package like so:

    ./bootstrap
    ./configure
    make
    make check
    make install
    
You can then run the samples in the `samples` directory.

------------------------------

###A note about copying

This project uses OpenSSL for large numbers and some cryptography algorithms. As such:

> This product includes cryptographic software written by Eric Young (eay@cryptsoft.com)

And when compiling for Windows:

> This product includes software written by Tim Hudson (tjs@cryptsoft.com)


The Autoconf macros under the `aclocal` directory are part of the [Autoconf Archive](http://www.gnu.org/software/autoconf-archive) and are subject to the licensing and copyright thereof.
