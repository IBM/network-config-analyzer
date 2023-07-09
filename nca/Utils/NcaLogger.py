#
# Copyright 2022 - IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import sys
from nca.Utils.Utils import Singleton


class NcaLogger(metaclass=Singleton):
    """
    NcaLogger is used to control warning messages issued by GenericYamlParser.
    Any warning message is sent to NcaLogger().log_message()

    The logger has 2 modes: muted / unmuted
    If muted -- it collects the warning messages instead of printing them to output.
    If unmuted -- the warning messages are printed directly to output without being collected.
    The function flush_messages() allows to print the collected messages and clear them.


    It is used for a 2-phase parsing of network config:
    First phase is done on mute mode.

    If "livesim" has potential to resolve some missing resources, a second parsing phase is called
    on unmute mode, for a combination of original resources + relevant livesim resources.

    Otherwise (no second parsing phase), the warning messages are flushed and printed to output.

    TODO: It is currently used mainly for muting printouts
          We may want to extend its functionality and use all printouts with it.
    """

    def __init__(self):
        self._is_mute = False
        self._collected_messages = []
        self._is_collecting_msgs = True

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

    def collect_msgs(self):
        """
        collect muted messages
        """
        self._is_collecting_msgs = True

    def dont_collect_msgs(self):
        """
        dont collect muted messages
        """
        self._is_collecting_msgs = False

    def is_collecting_msgs(self):
        """
        Return are muted messages being collected?
        :return: bool: True for collecting messages, False for not collecting messages.
        """
        return self._is_collecting_msgs

    def log_message(self, msg, file=None, level=None):
        """
        Log a message
        :param sting msg: message to log
        :param a file-like-object file: output stream
        :param str level: the level of the message: (I)nfo, (W)arning, (E)rror
        """
        if level == 'I':
            msg = f'Info: {msg}'
        elif level == 'W':
            msg = f'Warning: {msg}'
            if not file:
                file = sys.stderr
        elif level == 'E':
            msg = f'Error: {msg}'
            if not file:
                file = sys.stderr

        if self._is_collecting_msgs:
            if self.is_mute():
                self._collected_messages.append(msg)
            else:
                print(msg, file=file)

    def flush_messages(self, silent=False):
        """
        Flush all collected messages and print them (or not)
        :param bool silent: if silent is True don't print out the messages
        """
        if not silent and len(self._collected_messages) > 0:
            print(*self._collected_messages, sep="\n")
        self._collected_messages.clear()
