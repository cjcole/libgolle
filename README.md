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

###A note about copying

This project uses OpenSSL for large numbers and some cryptography algorithms (SHA. As such:

> This product includes cryptographic software written by Eric Young (eay@cryptsoft.com)

And when compiling for Windows:

> This product includes software written by Tim Hudson (tjs@cryptsoft.com)


The Autoconf macros used in this project are licensed under the 
[GNU Free Documentation License](http://www.gnu.org/software/autoconf-archive/GNU-Free-Documentation-License.html).
These include the macros under the `aclocal` directory.