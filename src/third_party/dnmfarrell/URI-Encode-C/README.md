encode_uri
==========
An optimized C library for percent encoding/decoding text

Description
-----------
This is a URI encoder/decoder written in C based on [RFC3986](https://tools.ietf.org/html/rfc3986).
This module always encodes characters that are not unreserved. When decoding,
invalid escape sequences are preserved.

The code is optimized for speed and has a reasonable test suite. It will also
encode and decode null bytes in the middle of strings (assuming you calculated
the string length correctly!).

Synopsis
--------

    #include <stdlib.h>
    #include <string.h>
    #include <uri_encode.h>

    /* encode text */
    const char *uri = "Some data!That Needs Encoding/";
    size_t len = strlen(uri);
    char buffer[ calc_buffer_size(uri) ];
    buffer[0] = '\0';
    uri_encode(uri, len, buffer);

    /* decode text */
    const char *encoded_uri = "Some%20data%21That%20Needs%20Decoding%2F";
    size_t len = strlen(encoded_uri);
    char decoded_uri[ len + 1 ];
    decoded_uri[0] = '\0';
    uri_decode(encoded_uri, len, decoded_uri);

Installation
------------

Builds, tests and installs a static library: `liburi_encode.a`

    clone https://github.com/dnmfarrell/Encode-URI-C.git
    cd Encode-URI-C
    make
    make test
    sudo make install

To install to a custom location, edit `DESTDIR` and `PREFIX` in `Makefile`.

Uninstallation
--------------

    sudo make uninstall

See Also
--------
* [URI-Encode-XS](https://github.com/dnmfarrell/URI-Encode-XS) is a Perl XS module
that uses the same C code.
* My article about the C code: [The road to a 55x speedup with XS](http://perltricks.com/article/the-road-to-a-55x-speedup-with-xs/)

Authors
-------
&copy; 2016

* [David Farrell](https://github.com/dnmfarrell)
* [Aristotle Pagaltzis](https://github.com/ap)
* [Christian Hansen](https://github.com/chansen)
* [Jesse DuMond](https://github.com/JesseCanary)

Version
-------
0.03

License
-------
See LICENSE
