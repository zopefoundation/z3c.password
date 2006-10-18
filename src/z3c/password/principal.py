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
"""Principal MixIn for Advnaced Password Management

$Id$
"""
__docformat__ = "reStructuredText"
import datetime
from z3c.password import interfaces

class PrincipalMixIn(object):
    """A Principal Mixin class for ``zope.app.principalfolder``'s internal
    principal."""

    passwordExpiresAfter = None
    maxFailedAttempts = None

    passwordSetOn = None
    failedAttempts = 0

    def getPassword(self):
        return super(PrincipalMixIn, self).getPassword()

    def setPassword(self, password, passwordManagerName=None):
        super(PrincipalMixIn, self).setPassword(password, passwordManagerName)
        self.passwordSetOn = datetime.datetime.now()
        self.failedAttempts = 0

    password = property(getPassword, setPassword)

    def checkPassword(self, pwd, ignoreExpiration=False, ignoreFailures=False):
        # Make sure the password has not been expired
        if not ignoreExpiration and self.passwordExpiresAfter is not None:
            expirationDate = self.passwordSetOn + self.passwordExpiresAfter
            if expirationDate < datetime.datetime.now():
                raise interfaces.PasswordExpired(self)
        # Check the password
        same = super(PrincipalMixIn, self).checkPassword(pwd)
        # If this was a failed attempt, record it, otherwise reset the failures
        if same and self.failedAttempts != 0:
            self.failedAttempts = 0
        if not same:
            self.failedAttempts += 1
        # If the maximum amount of failures has been reached notify the system
        # by sending an event and then raising an error.
        if not ignoreFailures and self.maxFailedAttempts is not None:
            if (self.maxFailedAttempts and
                self.failedAttempts > self.maxFailedAttempts):
                raise interfaces.TooManyLoginFailures(self)
        return same
