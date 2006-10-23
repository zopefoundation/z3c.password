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


The Principal Mix-in
--------------------

The principal mixin is a quick and functional example on how to use the
password utility and field. The mix-in class defines the following additional
attributes:


- ``passwordExpiresAfter``

  A time delta object that describes for how long the password is valid before
  a new one has to be specified. If ``None``, the password will never expire.

- ``maxFailedAttempts``

  An integer specifying the amount of failed attempts allowed to check the
  password before the password is locked and no new password can be provided.

- ``passwordSetOn``

  The date/time at which the password was last set. This value is used to
  determine the expiration of a password.

- ``failedAttempts``

  This is a counter that keeps track of the amount of failed login attempts
  since the last successful one. This value is used to determine when to lock
  the account after the maximum amount of failures has been reached.

Let's now create a principal:

  >>> from zope.app.authentication import principalfolder
  >>> from z3c.password import principal

  >>> class MyPrincipal(principal.PrincipalMixIn,
  ...                   principalfolder.InternalPrincipal):
  ...     pass

  >>> user = MyPrincipal('srichter', '123123', u'Stephan Richter')

Since the password has been immediately set, the ```passwordSetOn`` attribute
should have a value:

  >>> user.passwordSetOn
  datetime.datetime(...)

Initially, the amount of failed attempts is zero, ...

  >>> user.failedAttempts
  0

but after checking the password incorrectly, the value is updated:

  >>> user.checkPassword('456456')
  False
  >>> user.failedAttempts
  1

Initially there is no constraint on user, but let's add some:

  >>> user.passwordExpiresAfter
  >>> user.passwordExpiresAfter = datetime.timedelta(180)

  >>> user.maxFailedAttempts
  >>> user.maxFailedAttempts = 3

Let's now provide the incorrect password a couple more times:

  >>> user.checkPassword('456456')
  False
  >>> user.checkPassword('456456')
  False
  >>> user.checkPassword('456456')
  Traceback (most recent call last):
  ...
  TooManyLoginFailures: The password was entered incorrectly too often.

As you can see, once the maximum mount of attempts is reached, the system does
not allow you to log in at all anymore. At this point the password has to be
reset otherwise. However, you can tell the ``check()`` method explicitly to
ignore the failure count:

  >>> user.checkPassword('456456', ignoreFailures=True)
  False

Let's now reset the failure count.

  >>> user.failedAttempts = 0

Next we expire password:

  >>> user.passwordSetOn = datetime.datetime.now() + datetime.timedelta(-181)

A corresponding exception should be raised:

  >>> user.checkPassword('456456')
  Traceback (most recent call last):
  ...
  PasswordExpired: The password has expired.

Like for the too-many-failures exception above, you can explicitely turn off
the expiration check:

  >>> user.checkPassword('456456', ignoreExpiration=True)
  False

It is the responsibility of the presentation code to provide views for those
two exceptions. For the latter, it is common to allow the user to enter a new
password after providing the old one as verification.
