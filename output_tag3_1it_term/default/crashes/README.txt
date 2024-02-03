Command line used to find this crash:

afl-fuzz -i /data/memcached_bachelor_thesis/input_tag3 -o /data/memcached_bachelor_thesis/output_tag3_1it_term -s 42 -D -- /data/memcached_bachelor_thesis/testapp_goal3_Harness

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 0 B.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please post
to https://github.com/AFLplusplus/AFLplusplus/issues/286 once the issues
 are fixed :)

