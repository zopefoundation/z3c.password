##############################################################################
#
# Copyright (c) 2006 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Password Utility Interfaces
"""
import zope.interface
import zope.schema
from zope.i18n import translate

from z3c.password import MessageFactory as _


class InvalidPassword(zope.schema.ValidationError):
    """Invalid Password"""

    i18n_message = None

    def __str__(self):
        if self.i18n_message:
            return translate(self.i18n_message)
        return super(InvalidPassword, self).__str__()

    def doc(self):
        if self.i18n_message:
            return self.i18n_message
        return self.__class__.__doc__


class NoPassword(InvalidPassword):
    __doc__ = _('''No new password specified.''')


class TooShortPassword(InvalidPassword):
    __doc__ = _('''Password is too short.''')

    def __init__(self, minLength=None):
        super(TooShortPassword, self).__init__()
        self.minLength = minLength
        if minLength is not None:
            self.i18n_message = _(
                'Password is too short (minimum length: ${minLength}).',
                mapping=dict(minLength=minLength))


class TooLongPassword(InvalidPassword):
    __doc__ = _('''Password is too long.''')

    def __init__(self, maxLength=None):
        super(TooLongPassword, self).__init__()
        self.maxLength = maxLength
        if maxLength is not None:
            self.i18n_message = _(
                'Password is too long (maximum length: ${maxLength}).',
                mapping=dict(maxLength=maxLength))


class TooSimilarPassword(InvalidPassword):
    __doc__ = _('''Password is too similar to old one.''')

    def __init__(self, similarity=None, maxSimilarity=None):
        super(TooSimilarPassword, self).__init__()
        self.similarity = similarity
        self.maxSimilarity = maxSimilarity
        if similarity is not None and maxSimilarity is not None:
            self.i18n_message = _(
                'Password is too similar to old one'
                ' (similarity ${similarity}%, should be at most'
                ' ${maxSimilarity}%).',
                mapping=dict(similarity=int(round(similarity * 100)),
                             maxSimilarity=int(maxSimilarity * 100)))


class TooManyGroupCharacters(InvalidPassword):
    __doc__ = _('''Password contains too many characters of one group.''')

    def __init__(self, groupMax=None):
        super(TooManyGroupCharacters, self).__init__()
        self.groupMax = groupMax
        if groupMax is not None:
            self.i18n_message = _(
                'Password contains too many characters of one group'
                ' (should have at most ${groupMax}).',
                mapping=dict(groupMax=groupMax))


class TooFewGroupCharacters(InvalidPassword):
    __doc__ = _(
        '''Password does not contain enough characters of one group.''')


class TooFewGroupCharactersLowerLetter(TooFewGroupCharacters):
    __doc__ = _(
        'Password does not contain enough characters of lowercase letters.')

    def __init__(self, minLowerLetter=None):
        super(TooFewGroupCharactersLowerLetter, self).__init__()
        self.minLowerLetter = minLowerLetter
        if minLowerLetter is not None:
            self.i18n_message = _(
                'Password does not contain enough characters of lowercase'
                ' letters (should have at least ${minLowerLetter}).',
                mapping=dict(minLowerLetter=minLowerLetter))


class TooFewGroupCharactersUpperLetter(TooFewGroupCharacters):
    __doc__ = _(
        'Password does not contain enough characters of uppercase letters.')

    def __init__(self, minUpperLetter=None):
        super(TooFewGroupCharactersUpperLetter, self).__init__()
        self.minUpperLetter = minUpperLetter
        if minUpperLetter is not None:
            self.i18n_message = _(
                'Password does not contain enough characters of uppercase'
                ' letters (should have at least ${minUpperLetter}).',
                mapping=dict(minUpperLetter=minUpperLetter))


class TooFewGroupCharactersDigits(TooFewGroupCharacters):
    __doc__ = _('''Password does not contain enough characters of digits.''')

    def __init__(self, minDigits=None):
        super(TooFewGroupCharactersDigits, self).__init__()
        self.minDigits = minDigits
        if minDigits is not None:
            self.i18n_message = _(
                'Password does not contain enough characters of digits'
                ' (should have at least ${minDigits}).',
                mapping=dict(minDigits=minDigits))


class TooFewGroupCharactersSpecials(TooFewGroupCharacters):
    __doc__ = _(
        'Password does not contain enough characters of special characters.')

    def __init__(self, minSpecials=None):
        super(TooFewGroupCharactersSpecials, self).__init__()
        self.minSpecials = minSpecials
        if minSpecials is not None:
            self.i18n_message = _(
                'Password does not contain enough characters of special'
                ' characters (should have at least ${minSpecials}).',
                mapping=dict(minSpecials=minSpecials))


class TooFewGroupCharactersOthers(TooFewGroupCharacters):
    __doc__ = _(
        '''Password does not contain enough characters of other characters.''')

    def __init__(self, minOthers=None):
        super(TooFewGroupCharactersOthers, self).__init__()
        self.minOthers = minOthers
        if minOthers is not None:
            self.i18n_message = _(
                'Password does not contain enough characters of other'
                ' characters (should have at least ${minOthers}).',
                mapping=dict(minOthers=minOthers))


class TooFewUniqueCharacters(InvalidPassword):
    __doc__ = _('''Password does not contain enough unique characters.''')

    def __init__(self, minUniqueCharacters=None):
        super(TooFewUniqueCharacters, self).__init__()
        self.minUniqueCharacters = minUniqueCharacters
        if minUniqueCharacters is not None:
            self.i18n_message = _(
                'Password does not contain enough unique characters'
                ' (should have at least ${minUniqueCharacters}).',
                mapping=dict(minUniqueCharacters=minUniqueCharacters))


class TooFewUniqueLetters(InvalidPassword):
    __doc__ = _('''Password does not contain enough unique letters.''')

    def __init__(self, minUniqueLetters=None):
        super(TooFewUniqueLetters, self).__init__()
        self.minUniqueLetters = minUniqueLetters
        if minUniqueLetters is not None:
            self.i18n_message = _(
                'Password does not contain enough unique letters'
                ' (should have at least ${minUniqueLetters}).',
                mapping=dict(minUniqueLetters=minUniqueLetters))


class PasswordExpired(Exception):
    __doc__ = _('''The password has expired.''')

    def __init__(self, principal):
        self.principal = principal
        Exception.__init__(self, self.__doc__)


class PreviousPasswordNotAllowed(InvalidPassword):
    __doc__ = _('''The password set was already used before.''')

    def __init__(self, principal):
        self.principal = principal
        Exception.__init__(self, self.__doc__)


class TooManyLoginFailures(Exception):
    __doc__ = _('''The password was entered incorrectly too often.''')

    def __init__(self, principal):
        self.principal = principal
        Exception.__init__(self, self.__doc__)


TML_CHECK_ALL = None
TML_CHECK_NONRESOURCE = 'nonres'
TML_CHECK_POSTONLY = 'post'


class AccountLocked(Exception):
    __doc__ = _('The account is locked, because the password was '
                'entered incorrectly too often.')

    def __init__(self, principal):
        self.principal = principal
        Exception.__init__(self, self.__doc__)


class IPasswordUtility(zope.interface.Interface):
    """Component to verify and generate passwords.

    The purpose of this utility is to make common password-related tasks, such
    as verification and creation simple. However, only the collection of those
    utilites provide an overall net worth.
    """

    description = zope.schema.Text(
        title=_(u'Description'),
        description=_(u'A description of the password utility.'),
        required=False)

    def verify(new, ref=None):
        """Check whether the new password is valid.

        When a passward is good, the method simply returns, otherwise an
        ``InvalidPassword`` exception is raised.

        It is up to the implementation to define the semantics of a valid
        password. The sematics should ideally be described in the description.

        The ``ref`` argument is a reference password. In many scenarios it
        will be the old password, so that the method can ensure sufficient
        dissimilarity between the new and old password.
        """

    def generate(ref=None):
        """Generate a valid password.

        The ``ref`` argument is a reference password. In many scenarios it
        will be the old password, so that the method can ensure sufficient
        dissimilarity between the new and old password.
        """


class IHighSecurityPasswordUtility(IPasswordUtility):
    """A password utility for very secure passwords."""

    minLength = zope.schema.Int(
        title=_(u'Minimum Length'),
        description=_(u'The minimum length of the password.'),
        required=False,
        default=None)

    maxLength = zope.schema.Int(
        title=_(u'Maximum Length'),
        description=_(u'The maximum length of the password.'),
        required=False,
        default=None)

    @zope.interface.invariant
    def minMaxLength(task):
        if task.minLength is not None and task.maxLength is not None:
            if task.minLength > task.maxLength:
                raise zope.interface.Invalid(
                    u"Minimum length must not be greater than the maximum"
                    u" length.")

    groupMax = zope.schema.Int(
        title=_(u'Maximum Characters of Group'),
        description=_(u'The maximum amount of characters that a password can '
                      u'have from one group. The groups are: digits, letters, '
                      u'punctuation.'),
        required=False,
        default=None)

    maxSimilarity = zope.schema.Float(
        title=_(u'Old/New Similarity'),
        description=(
            u'The similarity ratio between the new and old password.'),
        required=False,
        default=None)

    minLowerLetter = zope.schema.Int(
        title=_(u'Minimum Number of Lowercase letters'),
        description=_(u'The minimum amount of lowercase letters that a '
                      u'password must have.'),
        required=False,
        default=None)

    minUpperLetter = zope.schema.Int(
        title=_(u'Minimum Number of Uppercase letters'),
        description=_(u'The minimum amount of uppercase letters that a '
                      u'password must have.'),
        required=False,
        default=None)

    minDigits = zope.schema.Int(
        title=_(u'Minimum Number of Numeric digits'),
        description=_(u'The minimum amount of numeric digits that a '
                      u'password must have.'),
        required=False,
        default=None)

    minSpecials = zope.schema.Int(
        title=_(u'Minimum Number of Special characters'),
        description=_(u'The minimum amount of special characters that a '
                      u'password must have.'),
        required=False,
        default=None)

    # WARNING! generating a password with Others is not yet supported
    minOthers = zope.schema.Int(
        title=_(u'Minimum Number of Other characters'),
        description=_(u'The minimum amount of other characters that a '
                      u'password must have.'),
        required=False,
        default=None)

    @zope.interface.invariant
    def saneMinimums(task):
        minl = 0
        if task.minLowerLetter:
            if task.minLowerLetter > task.groupMax:
                raise zope.interface.Invalid(
                    u"Any group minimum length must NOT be greater than "
                    u"the maximum group length.")

            minl += task.minLowerLetter
        if task.minUpperLetter:
            if task.minUpperLetter > task.groupMax:
                raise zope.interface.Invalid(
                    u"Any group minimum length must NOT be greater than "
                    u"the maximum group length.")

            minl += task.minUpperLetter
        if task.minDigits:
            if task.minDigits > task.groupMax:
                raise zope.interface.Invalid(
                    u"Any group minimum length must NOT be greater than "
                    u"the maximum group length.")

            minl += task.minDigits
        if task.minSpecials:
            if task.minSpecials > task.groupMax:
                raise zope.interface.Invalid(
                    u"Any group minimum length must NOT be greater than "
                    u"the maximum group length.")

            minl += task.minSpecials
        if task.minOthers:
            if task.minOthers > task.groupMax:
                raise zope.interface.Invalid(
                    u"Any group minimum length must NOT be greater than "
                    u"the maximum group length.")

            minl += task.minOthers

        if task.maxLength is not None:
            if minl > task.maxLength:
                raise zope.interface.Invalid(
                    u"Sum of group minimum lengths must NOT be greater than "
                    u"the maximum password length.")

    minUniqueLetters = zope.schema.Int(
        title=_(u'Minimum Number of Unique letters'),
        description=_(u'The minimum amount of unique letters that a '
                      u'password must have. This is against passwords '
                      u'like `aAaA0000`. All characters taken lowercase.'),
        required=False,
        default=None)

    @zope.interface.invariant
    def minUniqueLettersLength(task):
        if (task.minUniqueLetters is not None
                and task.minUniqueLetters is not None):
            if task.minUniqueLetters > task.maxLength:
                raise zope.interface.Invalid(
                    u"Minimum unique letters number must not be greater than "
                    u"the maximum length.")

    minUniqueCharacters = zope.schema.Int(
        title=_(u'Minimum Number of Unique characters'),
        description=_(u'The minimum amount of unique characters that a '
                      u'password must have. This is against passwords '
                      u'like `aAaA0000`. All characters taken lowercase.'),
        required=False,
        default=None)

    @zope.interface.invariant
    def minUniqueCharactersLength(task):
        if (task.minUniqueCharacters is not None
                and task.minUniqueCharacters is not None):
            if task.minUniqueCharacters > task.maxLength:
                raise zope.interface.Invalid(
                    u"Minimum unique characters length must not be greater"
                    u" than the maximum length.")


class IPasswordOptionsUtility(zope.interface.Interface):
    """Different general security options.

    The purpose of this utility is to make common password-related options
    available
    """

    changePasswordOnNextLogin = zope.schema.Bool(
        title=_(u'Password must be changed on next login'),
        description=_(u'Password must be changed on next login'),
        required=False,
        default=False)

    passwordExpiresAfter = zope.schema.Int(
        title=_(u'Password expires after (days)'),
        description=_(u'Password expires after (days)'),
        required=False,
        default=None)

    lockOutPeriod = zope.schema.Int(
        title=_(u'Lockout period (minutes)'),
        description=_(
            u'Lockout the user after too many failed password entries'
            u'for this many minutes. The user can try again after.'),
        required=False,
        default=None)

    maxFailedAttempts = zope.schema.Int(
        title=_(u'Max. number of failed password entries before account is'
                u' locked'),
        description=_(
            u'Specifies the amount of failed attempts allowed to check '
            u'the password before the password is locked and no new '
            u'password can be provided.'),
        required=False,
        default=None)

    failedAttemptCheck = zope.schema.Choice(
        title=_(u'Failed password check method'),
        description=_(u'Failed password check method. '
                      'All requests, non-reqource requests, POST requests.'),
        required=False,
        values=[TML_CHECK_ALL, TML_CHECK_NONRESOURCE, TML_CHECK_POSTONLY],
        default=TML_CHECK_ALL)

    disallowPasswordReuse = zope.schema.Bool(
        title=_(u'Disallow Password Reuse'),
        description=_(u'Do not allow to set a previously set password again.'),
        required=False,
        default=False)
