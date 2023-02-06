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

  >>> print(pwd.description)
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
  >>> print(pwd.maxSimilarity)
  0.6

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
  TooShortPassword: Password is too short (minimum length: 8).

  >>> pwd.verify('foobar-foobar')
  Traceback (most recent call last):
  ...
  TooLongPassword: Password is too long (maximum length: 12).

  >>> pwd.verify('fooBar12')

- Once the length is verified, the password is checked for similarity. If no
  reference password is provided, then this check always passes:

  >>> pwd.verify('fooBar12')

  >>> pwd.verify('fooBar12', 'fooBAR--')

  >>> pwd.verify('fooBar12', 'foobar12')
  Traceback (most recent call last):
  ...
  TooSimilarPassword: Password is too similar to old one (similarity 88%, should be at most 60%).

  >>> pwd2 = password.HighSecurityPasswordUtility()
  >>> pwd2.maxSimilarity = 0.999

  >>> pwd2.verify('fooBar12', 'fooBar12')
  Traceback (most recent call last):
  ...
  TooSimilarPassword: Password is too similar to old one (similarity 100%, should be at most 99%).

- The final check ensures that the password does not have too many characters
  of one group. The groups are: lower letters, upper letters, digits,
  punctuation, and others.

  >>> pwd.verify('fooBarBlah')
  Traceback (most recent call last):
  ...
  TooManyGroupCharacters: Password contains too many characters of one group (should have at most 6).

  >>> pwd.verify('FOOBARBlah')
  Traceback (most recent call last):
  ...
  TooManyGroupCharacters: Password contains too many characters of one group (should have at most 6).

  >>> pwd.verify('12345678')
  Traceback (most recent call last):
  ...
  TooManyGroupCharacters: Password contains too many characters of one group (should have at most 6).

  >>> pwd.verify('........')
  Traceback (most recent call last):
  ...
  TooManyGroupCharacters: Password contains too many characters of one group (should have at most 6).

  >>> pwd.verify(chr(0x0e1)*8)
  Traceback (most recent call last):
  ...
  TooManyGroupCharacters: Password contains too many characters of one group (should have at most 6).

Let's now verify a list of password that were provided by a bank:

  >>> for new in ('K7PzX2JZ', 'DznMLIww', 'ks59Ursq', 'YUcsuIrQ', 'bPEUFGSa',
  ...             'lUmtG0TP', 'ISfUKoTe', 'NKGY0aIJ', 'XyUuSHX4', 'CaFE1R5p'):
  ...     pwd.verify(new)

Let's now generate some passwords. To make them predictable, we specify a seed
when initializing the utility:

  >>> pwd = password.HighSecurityPasswordUtility(seed=8)

  >>> res = pwd.generate()
  >>> res in ['{l%ix~t8R', 'VWqy{fkrF'] # Py 2/3 diff in random.
  True

Force a LOT to make coverage happy:

  >>> for x in range(256):
  ...     _ =pwd.generate()


Even higher security settings
-----------------------------

We can specify how many of a selected character group we want to have in the
password.

We want to have at least 5 lowercase letters in the password:

  >>> pwd = password.HighSecurityPasswordUtility(seed=8)
  >>> pwd.minLowerLetter = 5

  >>> pwd.verify('FOOBAR123')
  Traceback (most recent call last):
  ...
  TooFewGroupCharactersLowerLetter: Password does not contain enough characters of lowercase letters (should have at least 5).

  >>> pwd.verify('foobAR123')
  Traceback (most recent call last):
  ...
  TooFewGroupCharactersLowerLetter: Password does not contain enough characters of lowercase letters (should have at least 5).

  >>> pwd.verify('foobaR123')

  >>> res = pwd.generate()
  >>> res in ['Us;iwbzM[J', 'VWqy{fkrF']
  True

We want to have at least 5 uppercase letters in the password:

  >>> pwd = password.HighSecurityPasswordUtility(seed=8)
  >>> pwd.minUpperLetter = 5

  >>> pwd.verify('foobar123')
  Traceback (most recent call last):
  ...
  TooFewGroupCharactersUpperLetter: Password does not contain enough characters of uppercase letters (should have at least 5).

  >>> pwd.verify('FOOBar123')
  Traceback (most recent call last):
  ...
  TooFewGroupCharactersUpperLetter: Password does not contain enough characters of uppercase letters (should have at least 5).

  >>> pwd.verify('fOOBAR123')

  >>> res = pwd.generate()
  >>> res in ['OvMPN3Bi', '[j#`(CSFbLRC']
  True

We want to have at least 5 digits in the password:

  >>> pwd = password.HighSecurityPasswordUtility(seed=8)
  >>> pwd.minDigits = 5

  >>> pwd.verify('foobar123')
  Traceback (most recent call last):
  ...
  TooFewGroupCharactersDigits: Password does not contain enough characters of digits (should have at least 5).

  >>> pwd.verify('FOOBa1234')
  Traceback (most recent call last):
  ...
  TooFewGroupCharactersDigits: Password does not contain enough characters of digits (should have at least 5).

  >>> pwd.verify('fOBA12345')

  >>> res = pwd.generate()
  >>> res in ['(526vK(>Z42v', 'Rv+3Dr0+501']
  True

We want to have at least 5 specials in the password:

  >>> pwd = password.HighSecurityPasswordUtility(seed=8)
  >>> pwd.minSpecials = 5

  >>> pwd.verify('foo(bar)')
  Traceback (most recent call last):
  ...
  TooFewGroupCharactersSpecials: Password does not contain enough characters of special characters (should have at least 5).

  >>> pwd.verify('FO.#(Ba1)')
  Traceback (most recent call last):
  ...
  TooFewGroupCharactersSpecials: Password does not contain enough characters of special characters (should have at least 5).

  >>> pwd.verify('fO.,;()5')

  >>> res = pwd.generate()
  >>> res in ['?d{*~2q|P', 's:i(e!`ys-6~']
  True

We want to have at least 5 others in the password:

  >>> pwd = password.HighSecurityPasswordUtility(seed=8)
  >>> pwd.minOthers = 5

  >>> pwd.verify('foobar'+chr(0x0c3)+chr(0x0c4))
  Traceback (most recent call last):
  ...
  TooFewGroupCharactersOthers: Password does not contain enough characters of other characters (should have at least 5).

  >>> pwd.verify('foobar'+chr(0x0c3)+chr(0x0c4)+chr(0x0e1))
  Traceback (most recent call last):
  ...
  TooFewGroupCharactersOthers: Password does not contain enough characters of other characters (should have at least 5).

  >>> pwd.verify('fOO'+chr(0x0e1)*5)


Generating passwords with others not yet supported

  #>>> pwd.generate()
  #'?d{*~2q|P'
  #
  #>>> pwd.generate()
  #'(8a5\\(^}vB'

We want to have at least 5 different characters in the password:

  >>> pwd = password.HighSecurityPasswordUtility(seed=8)
  >>> pwd.minUniqueCharacters = 5

  >>> pwd.verify('foofoo1212')
  Traceback (most recent call last):
  ...
  TooFewUniqueCharacters: Password does not contain enough unique characters (should have at least 5).

  >>> pwd.verify('FOOfoo2323')
  Traceback (most recent call last):
  ...
  TooFewUniqueCharacters: Password does not contain enough unique characters (should have at least 5).

  >>> pwd.verify('fOOBAR123')

  >>> res = pwd.generate()
  >>> res in ['{l%ix~t8R', 'VWqy{fkrF']
  True

We want to have at least 5 different letters in the password:

  >>> pwd = password.HighSecurityPasswordUtility(seed=8)
  >>> pwd.minUniqueLetters = 5

  >>> pwd.verify('foofoo1212')
  Traceback (most recent call last):
  ...
  TooFewUniqueLetters: Password does not contain enough unique letters (should have at least 5).

  >>> pwd.verify('FOOBfoob2323')
  Traceback (most recent call last):
  ...
  TooFewUniqueLetters: Password does not contain enough unique letters (should have at least 5).

  >>> pwd.verify('fOOBAR123')

  >>> res = pwd.generate()
  >>> res in ['{l%ix~t8R', 'VWqy{fkrF']
  True


The Password Field
------------------

The password field can be used to specify an advanced password. It extends the
standard ``zope.schema`` password field with the ``checker`` attribute. The
checker is either a password utility (as specified above) or the name of such a
a utility. The checker is used to verify whether a password is acceptable or
not.

Let's now create the field:

  >>> import datetime
  >>> from zope.password.password import PlainTextPasswordManager
  >>> from z3c.password import field

  >>> pwd = password.HighSecurityPasswordUtility(seed=8)

  >>> pwdField = field.Password(
  ...     __name__='password',
  ...     title='Password',
  ...     checker=pwd)

Let's validate a value:

  >>> pwdField.validate('fooBar12')
  >>> pwdField.validate('fooBar')
  Traceback (most recent call last):
  ...
  TooShortPassword: Password is too short (minimum length: 8).

Validation must work on bound fields too:

Let's now create a principal:

  >>> from zope.pluggableauth.plugins import principalfolder
  >>> from z3c.password import principal

  >>> class MyPrincipal(principal.PrincipalMixIn,
  ...                   principalfolder.InternalPrincipal):
  ...     pass

  >>> user = MyPrincipal('srichter', '123123', 'Stephan Richter')

Bind the field:

  >>> bound = pwdField.bind(user)

  >>> bound.validate('fooBar12')
  >>> bound.validate('fooBar')
  Traceback (most recent call last):
  ...
  TooShortPassword: Password is too short (minimum length: 8).

Let's create a principal without the PrincipalMixIn:

  >>> user = principalfolder.InternalPrincipal('srichter', '123123',
  ...     'Stephan Richter')

Bind the field:

  >>> bound = pwdField.bind(user)

  >>> bound.validate('fooBar12')
  >>> bound.validate('fooBar')
  Traceback (most recent call last):
  ...
  TooShortPassword: Password is too short (minimum length: 8).


Other common usecase is to do a utility and specify it's name as checker.

  >>> import zope.component
  >>> zope.component.provideUtility(pwd, name='my password checker')

Recreate the field:

  >>> pwdField = field.Password(
  ...     __name__='password',
  ...     title='Password',
  ...     checker='my password checker')

Let's validate a value:

  >>> pwdField.validate('fooBar12')
  >>> pwdField.validate('fooBar')
  Traceback (most recent call last):
  ...
  TooShortPassword: Password is too short (minimum length: 8).


Edge cases.

No checker specified.

  >>> pwdField = field.Password(
  ...     __name__='password',
  ...     title='Password')

Validation silently succeeds with a checker:

  >>> pwdField.validate('fooBar12')
  >>> pwdField.validate('fooBar')

Bad utility name.

  >>> pwdField = field.Password(
  ...     __name__='password',
  ...     title='Password',
  ...     checker='foobar password checker')

Burps on the utility lookup as expected:

  >>> pwdField.validate('fooBar12')
  Traceback (most recent call last):
  ...
  ComponentLookupError:...

Bound object does not have the property:

  >>> pwdField = field.Password(
  ...     __name__='foobar',
  ...     title='Password',
  ...     checker=pwd)

  >>> bound = pwdField.bind(user)

Validation silently succeeds:

  >>> bound.validate('fooBar12')
