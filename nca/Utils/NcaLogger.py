#
# Copyright 2022 - IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import sys


class Singleton(type):
    """
    A metaclass implementing singleton for NcaLogger
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class NcaLogger(metaclass=Singleton):
    """
    The logger.

    TODO: It is currently used mainly for muting printouts
          We may want to extend its functionality and use all printouts with it.
    """

    def __init__(self):
        self._is_mute = False
        self._collected_messages = []

    def mute(self):
        """
        Silence printouts
        """
        self._is_mute = True

    def unmute(self):
        """
        Activate printouts
        """
        self._is_mute = False

    def is_mute(self):
        """
        Return are printouts muted?
        :return: bool: True for mute, False for active.
        """
        return self._is_mute

    def log_message(self, msg, file=sys.stdout):
        """
        Log a message
        :param sting msg: message to log
        :param a file-like-object file: output stream
        """
        if self.is_mute():
            self._collected_messages.append(msg)
        else:
            # print(msg, file)
            print(msg)

    def flush_messages(self, silent=False):
        """
        Flush all collected messages and print them (or not)
        :param bool silent: if silent is True don't print out the messages
        """
        if not silent:
            print(self._collected_messages)
        self._collected_messages.clear()
