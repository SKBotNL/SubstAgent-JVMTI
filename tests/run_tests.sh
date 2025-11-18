#!/bin/bash
set -u
TESTS_COUNT=14
TEST_DESCRIPTIONS=(
    "\$SAME_LENGTH_ENV where everything fits in one byte array"
    "\$SHORTER_ENV where everything fits in one byte array"
    "\$LONGER_ENV where everything fits in one byte array"
    "\$SAME_LENGTH_ENV split in 2 byte arrays, only the read content overflows"
    "\$SHORTER_ENV split in 2 byte arrays, only the read content overflows"
    "\$LONGER_ENV split in 2 byte arrays, only the read content overflows"
    "\$SAME_LENGTH_ENV split in 3 byte arrays, the entirety of the read content overflows"
    "\$SHORTER_ENV split in 3 byte arrays, the entirety of the read content overflows"
    "\$LONGER_ENV split in 3 byte arrays, the entirety of the read content overflows"
    "\$SAME_LENGTH_ENV at the end of the file"
    "\$SHORTER_ENV at the end of the file"
    "Overflowing \$SHORTER_ENV"
    "File that is not a config file"
    "Reading really big file"
)

# Build SubstAgent
echo -n "Compiling SubstAgent..."
cd ../build
output=$(make 2>&1)
if [ $? -ne 0 ]; then
    echo -e "\e[0;31mBuild failed\e[0m"
    echo "$output"
    exit 1
fi
echo -ne "\e[2K\r"
echo "Done compiling SubstAgent"
cd ../tests

substagent_path=$(realpath "../build/libsubstagent.so")

# Cleanup
rm -rf ./build
mkdir ./build

# Compile tests
# echo -n "Compiling test "
# tests_count_digits=${#TESTS_COUNT}
# for (( TEST=1; TEST<=TESTS_COUNT; TEST++ )); do
#     echo -n "$TEST/$TESTS_COUNT"
#     javac Test$TEST.java -d ./build
#     if [ $? -ne 0 ]; then
        # echo -e "\e[0;31mCould not compile test $TEST\e[0m"
        # exit 1
#     fi
#     test_digits=${#TEST}
#     shift_left=$(( tests_count_digits + test_digits + 1 ))
#     echo -ne "\e[${shift_left}D"
# done
# echo -ne "\e[2K\r"
# echo "Done compiling tests"

echo -n "Compiling tests..."
pids=()
for (( TEST=1; TEST<=TESTS_COUNT; TEST++ )); do
    javac Test$TEST.java -d ./build &
    pids+=($!)
done

for pid in "${pids[@]}"; do
    wait "$pid"
    if [ $? -ne 0 ]; then
        echo -e "\e[0;31mCould not compile test $TEST\e[0m"
        exit 1
    fi
done

echo -ne "\e[2K\r"
echo "Done compiling tests"

cp .env ./build

# Run tests
cd ./build

a_test_has_failed=false
for (( TEST=1; TEST<=TESTS_COUNT; TEST++ )); do
    output=$(java -agentpath:$substagent_path Test$TEST 2>&1)
    if [ $? -eq 0 ]; then
        echo -e "\e[0;32m✓ Test $TEST passed - ${TEST_DESCRIPTIONS[$TEST-1]}\e[0m"
    else
        echo -e "\e[0;31m✗ Test $TEST failed - ${TEST_DESCRIPTIONS[$TEST-1]}\e[0m"
        a_test_has_failed=true
        echo "$output"
    fi
done

echo "=================="
if [ "$a_test_has_failed" == true ] ; then
    echo -e "\e[0;31m✗ One or more tests failed\e[0m"
else
    echo -e "\e[0;32m✓ All tests passed\e[0m"
fi