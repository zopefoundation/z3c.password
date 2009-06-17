============================
Advnaced Password Management
============================

This package provides an API and implementation of a password generation and
verification utility. A high-security implementation is provided that is
suitable for banks and other high-security institutions. The package also
offers a field and a property for those fields.

The Password Utility
--------------------

The password utilities are located in the ``password`` module.

  >>> from z3c.password import password

The module provides a trivial sample and a high-security implementation of the
utility. The password utility provides two methods.

  >>> pwd = password.TrivialPasswordUtility()

The first is to verify the password. The first argument is the new password
and the second, optional argument a reference password, usually the old
one. When the verification fails an ``InvalidPassword`` exception is raised,
otherwise the method simply returns. In the case of the trivial password
utility, this method always returns:

  >>> pwd.verify('foo')
  >>> pwd.verify('foobar', 'foo')

The second method generates a password conform to the security constraints of
the password utility. The trivial password utility always returns the password
"trivial".

  >>> pwd.generate()
  'trivial'
  >>> pwd.generate('foo')
  'trivial'

The ``generate()`` method also accepts the optional reference
password. Finally, each password utility must provide a description explaining
its security constraints:

  >>> print pwd.description
  All passwords are accepted and always the "trivial" password is generated.

Let's now look at the high-security password utility. In its constructor you
can specify several constraints; the minimum and maximum length of the
password, the maximum of characters of one group (lower letters, upper
letters, digits, punctuation, other), and the maximum similarity score.

  >>> pwd = password.HighSecurityPasswordUtility()
  >>> pwd.minLength
  8
  >>> pwd.maxLength
  12
  >>> pwd.groupMax
  6
  >>> pwd.maxSimilarity
  0.59999999999999998

- When the password is empty, then the password is invalid:

  >>> pwd.verify(None)
  Traceback (most recent call last):
  ...
  NoPassword

  >>> pwd.verify('')
  Traceback (most recent call last):
  ...
  NoPassword

  >>> pwd.verify('', 'other')
  Traceback (most recent call last):
  ...
  NoPassword

- Next, it is verified that the password has the correct length:

  >>> pwd.verify('foo')
  Traceback (most recent call last):
  ...
  TooShortPassword

  >>> pwd.verify('foobar-foobar')
  Traceback (most recent call last):
  ...
  TooLongPassword

  >>> pwd.verify('fooBar12')

- Once the length is verified, the password is checked for similarity. If no
  reference password is provided, then this check always passes:

  >>> pwd.verify('fooBar12')

  >>> pwd.verify('fooBar12', 'fooBAR--')

  >>> pwd.verify('fooBar12', 'foobar12')
  Traceback (most recent call last):
  ...
  TooSimilarPassword

- The final check ensures that the password does not have too many characters
  of one group. The groups are: lower letters, upper letters, digits,
  punctuation, and others.

  >>> pwd.verify('fooBarBlah')
  Traceback (most recent call last):
  ...
  TooManyGroupCharacters

  >>> pwd.verify('FOOBARBlah')
  Traceback (most recent call last):
  ...
  TooManyGroupCharacters

  >>> pwd.verify('12345678')
  Traceback (most recent call last):
  ...
  TooManyGroupCharacters

  >>> pwd.verify('........')
  Traceback (most recent call last):
  ...
  TooManyGroupCharacters

  >>> pwd.verify(unichr(0x0e1)*8)
  Traceback (most recent call last):
  ...
  TooManyGroupCharacters

Let's now verify a list of password that were provided by a bank:

  >>> for new in ('K7PzX2JZ', 'DznMLIww', 'ks59Ursq', 'YUcsuIrQ', 'bPEUFGSa',
  ...             'lUmtG0TP', 'ISfUKoTe', 'NKGY0aIJ', 'XyUuSHX4', 'CaFE1R5p'):
  ...     pwd.verify(new)

Let's now generate some passwords. To make them predictable, we specify a seed
when initializing the utility:

  >>> pwd = password.HighSecurityPasswordUtility(seed=8)

  >>> pwd.generate()
  '{l%ix~t8R'
  >>> pwd.generate()
  'Us;iwbzM[J'

Force a LOT to make coverage happy:

  >>> for x in xrange(256):
  ...     _ =pwd.generate()



The Password Field
------------------

The password field can be used to specify an advanced password. It extends the
standard ``zope.schema`` password field with the ``checker`` attribute. The
checker is either a password utility (as specified above) or the name of sucha
a utility. The checker is used to verify whether a password is acceptable or
not.

Let's now create the field:

  >>> import datetime
  >>> from zope.app.authentication.password import PlainTextPasswordManager
  >>> from z3c.password import field

  >>> pwdField = field.Password(
  ...     __name__='password',
  ...     title=u'Password',
  ...     checker=pwd)

Let's validate a value:

  >>> pwdField.validate(u'fooBar12')
  >>> pwdField.validate(u'fooBar')
  Traceback (most recent call last):
  ...
  TooShortPassword

