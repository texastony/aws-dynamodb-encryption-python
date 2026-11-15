# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Helper utilities for integration tests."""
import os

import pytest

# convenience imports
try:
    from ..functional import hypothesis_strategies  # noqa=F401 pylint: disable=unused-import
    from ..functional import functional_test_utils
except (ImportError, ValueError, SystemError):
    if "AWS_ENCRYPTION_SDK_EXAMPLES_TESTING" not in os.environ:
        raise

DDB_TABLE_NAME = "DDB_ENCRYPTION_CLIENT_TEST_TABLE_NAME"


@pytest.fixture
def ddb_table_name():
    """Retrieve the target DynamoDB table from environment variable."""
    try:
        return os.environ[DDB_TABLE_NAME]
    except KeyError:
        raise ValueError(
            (
                "Environment variable '{}' must be set to the correct DynamoDB table name"
                " for integration tests to run"
            ).format(DDB_TABLE_NAME)
        )
