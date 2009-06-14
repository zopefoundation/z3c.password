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
"""Principal MixIn for Advanced Password Management

$Id$
"""
__docformat__ = "reStructuredText"
import datetime
import zope.component
from z3c.password import interfaces

class PrincipalMixIn(object):
    """A Principal Mixin class for ``zope.app.principalfolder``'s internal
    principal."""

    passwordExpiresAfter = None
    passwordSetOn = None
    passwordExpired = False #force PasswordExpired,
                             #e.g. for changePasswordOnNextLogin

    failedAttempts = 0
    maxFailedAttempts = None
    lockedOutOn = None
    lockOutPeriod = None

    def getPassword(self):
        return super(PrincipalMixIn, self).getPassword()

    def setPassword(self, password, passwordManagerName=None):
        super(PrincipalMixIn, self).setPassword(password, passwordManagerName)
        self.passwordSetOn = self.now()
        self.failedAttempts = 0
        self.passwordExpired = False

    password = property(getPassword, setPassword)

    def now(self):
        #hook to facilitate testing and easier override
        return datetime.datetime.now()

    def checkPassword(self, pwd, ignoreExpiration=False, ignoreFailures=False):
        # Check the password
        same = super(PrincipalMixIn, self).checkPassword(pwd)

        if not ignoreFailures and self.lockedOutOn is not None:
            lockPeriod = self._lockOutPeriod()
            if lockPeriod is not None:
                #check if the user locked himself previously
                if self.lockedOutOn + lockPeriod > self.now():
                    if not same:
                        self.lockedOutOn = self.now()
                    raise interfaces.AccountLocked(self)
                else:
                    self.failedAttempts = 0
                    self.lockedOutOn = None

        # If this was a failed attempt, record it, otherwise reset the failures
        if same and self.failedAttempts != 0:
            self.failedAttempts = 0
            self.lockedOutOn = None
        if not same:
            self.failedAttempts += 1
        # If the maximum amount of failures has been reached notify the system
        # by raising an error.
        if not ignoreFailures:
            attempts = self._maxFailedAttempts()
            if attempts is not None:
                if (attempts and self.failedAttempts > attempts):
                    #record the time when TooManyLoginFailures happened
                    self.lockedOutOn = self.now()

                    raise interfaces.TooManyLoginFailures(self)

        if same:
            if not ignoreExpiration:
                if self.passwordExpired:
                    raise interfaces.PasswordExpired(self)

                # Make sure the password has not been expired
                expires = self._passwordExpiresAfter()
                if expires is not None:
                    if self.passwordSetOn + expires < self.now():
                        raise interfaces.PasswordExpired(self)

        return same

    def _optionsUtility(self):
        return zope.component.queryUtility(
            interfaces.IPasswordOptionsUtility, default=None)

    def _passwordExpiresAfter(self):
        if self.passwordExpiresAfter is not None:
            return self.passwordExpiresAfter

        options = self._optionsUtility()
        if options is None:
            return self.passwordExpiresAfter
        else:
            if options.passwordExpiresAfter:
                return datetime.timedelta(days=options.passwordExpiresAfter)
            else:
                return self.passwordExpiresAfter

    def _lockOutPeriod(self):
        if self.lockOutPeriod is not None:
            return self.lockOutPeriod

        options = self._optionsUtility()
        if options is None:
            return self.lockOutPeriod
        else:
            if options.lockOutPeriod:
                return datetime.timedelta(minutes=options.lockOutPeriod)
            else:
                return self.lockOutPeriod

    def _maxFailedAttempts(self):
        if self.maxFailedAttempts is not None:
            return self.maxFailedAttempts

        options = self._optionsUtility()
        if options is None:
            return self.maxFailedAttempts
        else:
            if options.maxFailedAttempts:
                return options.maxFailedAttempts
            else:
                return self.maxFailedAttempts