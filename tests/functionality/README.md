# Tests

This folder holds the test suite for Retina's functionality. New retina applications can be added and tested using the script.py handler.
The handler will display whether the given expected output file matches the output file produced by the test.

To perform tests, run this command from the main retina directory using the appropriate arguments.

`sudo ./tests/functionality/script.py [app_name] [expected_output_file_path] [output_file_path] [pcap_file]`

For some tests, including the basic_test, a pcap_file is not necessary if running Retina offline. In that scenario, you may pass anything into this argument.
