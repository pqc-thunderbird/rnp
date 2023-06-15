#!/bin/bash

# install this hook as
# $ cd rnp/.git/hooks 
# $ ln -s ../../git-hooks/pre-commit-clang-check-all.sh pre-commit
#
# Note that the executable clang-format-check-all-11 must be in your path.
# Note also that this hook checks all files under src/ and include/ irrespectively of whether they are part of the commit or not.

set -e
clang-format-check-all-11 src/ include/
