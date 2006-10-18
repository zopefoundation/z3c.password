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

$Id$
"""
__docformat__ = "reStructuredText"
import zope.interface
import zope.schema
from zope.exceptions.interfaces import UserError

from z3c.password import MessageFactory as _

class InvalidPassword(zope.schema.ValidationError):
    """Invalid Password"""

class NoPassword(InvalidPassword):
    __doc__ = _('''No new password specified.''')

class TooShortPassword(InvalidPassword):
    __doc__ = _('''Password is too short.''')

class TooLongPassword(InvalidPassword):
    __doc__ = _('''Password is too long.''')

class TooSimilarPassword(InvalidPassword):
    __doc__ = _('''Password is too similar to old one.''')

class TooManyGroupCharacters(InvalidPassword):
    __doc__ = _('''Password contains too many characters of one group.''')

class PasswordExpired(Exception):
    __doc__ = _('''The password has expired.''')

    def __init__(self, principal):
        self.principal = principal
        Exception.__init__(self, self.__doc__)

class TooManyLoginFailures(Exception):
    __doc__ = _('''The password was entered incorrectly too often.''')

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
            if task.minLength > task.minLength:
                raise zope.interface.Invalid(
                    u"Minimum lnegth must be greater than the maximum length.")

    groupMax = zope.schema.Int(
        title=_(u'Maximum Characters of Group'),
        description=_(u'The maximum amount of characters that a password can '
                      u'have from one group. The groups are: digits, letters, '
                      u'punctuation.'),
        required=False,
        default=None)

    maxSimilarity = zope.schema.Float(
        title=_(u'Old/New Similarity'),
        description=(u'The similarity ratio between the new and old password.'),
        required=False,
        default=None)
