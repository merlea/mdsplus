dispatch /command /server=localhost:9999 set tree distest /shot=1
wait 1
dispatch /command /server=localhost:9999 dispatch/build/monitor=localhost:9997
wait 1
dispatch /command /server=localhost:9999 dispatch/phase/monitor=localhost:9997 init
wait 1
