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

$Id$
"""
__docformat__ = "reStructuredText"

import zope.component
from zope.app.authentication import password
from zope.app.testing import placelesssetup


def setUp(test):
    placelesssetup.setUp(test)
    zope.component.provideUtility(
        password.PlainTextPasswordManager(), name='Plain Text')


def tearDown(test):
    placelesssetup.tearDown(test)


class TestBrowserRequest():
    """pretty dumb test request"""

    def __init__(self, url, method='GET'):
        self.URL = url
        self.method = method
        self.interaction = None

    def getURL(self):
        return self.URL
