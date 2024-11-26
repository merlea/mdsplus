#!/bin/bash

export distest_path=/tmp/$USER/distest

mkdir -p $distest_path

mdsip -p 9997 -s > server_9997.log 2> server_9997.err & # Monitor server
mdsip -p 9998 -s > server_9998.log 2> server_9998.err & # Action server
mdsip -p 9999 -s > server_9999.log 2> server_9999.err & # Dispatch server
actlog -monitor localhost:9997 > actlog.log 2> actlog.err &

mdstcl @build_tree

mdstcl @test_action

pkill -P $$
