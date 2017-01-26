# Copyright (c) 2017 Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

import re

"""Utilities for handling DNS hostnames"""


def is_valid_hostname(hostname):
    """
    Check if the parameter is a valid hostname.

    @type hostname: str or bytearray
    @rtype: boolean
    """
    try:
        if not isinstance(hostname, str):
            hostname = hostname.decode('ascii', 'strict')
    except UnicodeDecodeError:
        return False
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False

    # must not be all-numeric, so that it can't be confused with an ip-address
    if re.match(r"[\d.]+$", hostname):
        return False

    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))
