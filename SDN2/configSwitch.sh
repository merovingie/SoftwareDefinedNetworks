#!/usr/bin/env bash

# change switch protocool:
ovs-vsctl set bridge s1 protocols=OpenFlow13
ovs-vsctl set bridge s2 protocols=OpenFlow13
ovs-vsctl set bridge s3 protocols=OpenFlow13
