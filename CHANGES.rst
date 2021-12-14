=======
CHANGES
=======

1.1.0 (2021-12-14)
------------------

- Add support for Python 3.8, 3.9 and 3.10.

- Drop support for Python 3.4.


1.0.0 (2018-11-14)
------------------

- Add support for Python 3.6 and 3.7. Drop support for Python 3.5 and
  below. Drop Python 2.6 support.

- Drop support for ``None`` passwords, since they are not supported in the
  underlying APIs anymore.


1.0.0a1 (2013-02-28)
--------------------

- Add support for Python 3.3.

- Drop dependency on ``zope.app.testing`` and ``zope.app.authentication``.

- Replace deprecated ``zope.interface.implements`` usage with equivalent
  ``zope.interface.implementer`` decorator.

- Drop support for Python 2.4 and 2.5.


0.11.1 (2012-09-19)
-------------------

- ``TooSimilarPassword``: do not round ``maxSimilarity`` up, because we
  sometimes use 0.999 to avoid the same password set.
  0.999 would be displayed as 100% (100% vs. 100%)


0.11.0 (2012-08-09)
-------------------

- Better error messages for invalid password exceptions (when you reject the
  user's password for being too short or too long, it's only polite to tell
  them what the minimum/maximum password length is).

  This introduces new translatable strings which haven't been translated yet.


0.10.1 (2011-03-28)
-------------------

- Minor changes:

  * Password field: added ignoreEmpty=False parameter
  * previousPasswords: always set the property, not just append
  * some caching of IPasswordOptionsUtility property usage


0.10.0 (2010-03-24)
-------------------

- Check for relevancy of the request when counting failed login attempts as
  early as possible. This prevents account locked errors raised for things like
  resources.

0.9.0 (2010-02-18)
------------------

- Added Dutch translations (janwijbrand)

0.8.0 (2009-01-29)
------------------

- Feature: ``failedAttemptCheck``:

  * increment failedAttempts on all/any request (this is the default)
  * increment failedAttempts only on non-resource requests
  * increment failedAttempts only on POST requests

- Feature: more specific exceptions on new password verification.

0.7.4 (2009-12-22)
------------------

- Fix: ``PrincipalMixIn.passwordSetOn`` happens to be ``None`` in case the
  class is mixed in after the user was created, that caused a bug.

0.7.3 (2009-12-08)
------------------

- Fix: ``disallowPasswordReuse`` must not check ``None`` passwords.

0.7.2 (2009-08-07)
------------------

- German translations

0.7.1 (2009-07-02)
------------------

- Feature: ``passwordOptionsUtilityName`` property on the ``PrincipalMixIn``.
  This allows to set different options for a set of users instead of storing
  the direct values on the principal.


0.7.0 (2009-06-22)
------------------

- Feature: Even harder password settings:

  * ``minLowerLetter``
  * ``minUpperLetter``
  * ``minDigits``
  * ``minSpecials``
  * ``minOthers``
  * ``minUniqueCharacters``
  * ``minUniqueLetters``: count and do not allow less then specified number

- Feature:

  * ``disallowPasswordReuse``: do not allow to set a previously used password

- 100% test coverage

0.6.0 (2009-06-17)
------------------

- Features:

  ``PrincipalMixIn`` got some new properties:

  * ``passwordExpired``: to force the expiry of the password
  * ``lockOutPeriod``: to enable automatic lock and unlock on too many bad tries

  ``IPasswordOptionsUtility`` to have global password options:

  * ``changePasswordOnNextLogin``: not implemented here, use
    PrincipalMixIn.passwordExpired
  * ``lockOutPeriod``: global counterpart of the PrincipalMixIn property
  * ``passwordExpiresAfter``: global counterpart of the PrincipalMixIn property
  * ``maxFailedAttempts``: global counterpart of the PrincipalMixIn property

  Password checking goes like this (on the high level):

  1. raise AccountLocked if too many bad tries and account should be locked
  2. raise PasswordExpired if expired AND password matches
  3. raise TooManyLoginFailures if too many bad tries
  4. return whether password matches

  More details in ``principal.txt``

- Added Russian translation

- Refactor PrincipalMixIn now() into a separate method to facilitate
  override and testing

- Changed the order the password is checked:

  1. check password against stored
  2. check maxFailedAttempts, raise TooManyLoginFailures if over
  3. if password is OK, check expirationDate, raise PasswordExpired if over
  4. return whether password matches

  This is because I need to be sure that PasswordExpired is raised only if the
  password *IS* valid. Entering an invalid password *MUST NOT* raise
  PasswordExpired, because I want to use PasswordExpired to allow the user
  to change it's password. This should not happen if the user did not enter a
  valid password.

0.5.0 (2008-10-21)
------------------

- Initial Release
