# toytls

## Disclaimer - DO NOT USE THIS LIBRARY

`toytls` was written using Python 3 in March to May 2020, as an exercise to understand
TLS 1.2, Python 3 typing annotations and the `async`/`await` syntax.

As the result of a learning exercise, this library will crumble like wet cardboard if
confronted with any kind of adverse network conditions or unexpected/malformed TLS messages.

In other words, beyond its teaching value in helping understanding TLS, this library should not be
used by anyone, for any purpose.

## Dependencies

The dependencies are listed in `requirements.txt`.

## toytls.https

`toytls.https` can be used to make a HTTP 1.1 `GET` request on a given URL.

It can be used on the command line: `python -m toytls.https https://www.google.com`

Given the `toytls` disclaimer, this command-line should only be used to connect to trusted
web servers.
