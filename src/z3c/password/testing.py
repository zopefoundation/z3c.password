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
"""Test Setup
"""
import zope.component
import zope.component.testing
from zope.password import password


def setUp(test):
    zope.component.testing.setUp(test)

    from zope.security.management import newInteraction
    newInteraction()

    zope.component.provideUtility(
        password.PlainTextPasswordManager(), name='SSHA')
    zope.component.provideUtility(
        password.PlainTextPasswordManager(), name='Plain Text')


def tearDown(test):
    zope.component.testing.tearDown(test)


class TestBrowserRequest():
    """pretty dumb test request"""

    def __init__(self, url, method='GET'):
        self.URL = url
        self.method = method
        self.interaction = None

    def getURL(self):
        return self.URL
