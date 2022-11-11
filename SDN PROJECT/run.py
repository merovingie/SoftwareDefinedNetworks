#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

from ryu.cmd import manager


def main():
    sys.argv.append('--observe-links')
    sys.argv.append('--config-file')
    sys.argv.append('ryu.conf')
    # sys.argv.append('6633')
    sys.argv.append('project1_controller.py')
    # sys.argv.append('--verbose')
    # sys.argv.append('--enable-debugger')
    manager.main()

if __name__ == '__main__':
    main()
