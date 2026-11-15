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
"""Helper tools for use in tests."""
from __future__ import division

import copy
import itertools
import os
import socket
from collections import defaultdict
from decimal import Decimal
from unittest.mock import AsyncMock, patch

import aioboto3
import boto3
import pytest
from boto3.dynamodb.types import Binary
from moto.server import ThreadedMotoServer

from dynamodb_encryption_sdk_async.delegated_keys.jce import JceNameLocalDelegatedKey
from dynamodb_encryption_sdk_async.encrypted.client import EncryptedClient
from dynamodb_encryption_sdk_async.encrypted.item import decrypt_python_item, encrypt_python_item
from dynamodb_encryption_sdk_async.encrypted.resource import EncryptedResource
from dynamodb_encryption_sdk_async.encrypted.table import EncryptedTable
from dynamodb_encryption_sdk_async.identifiers import CryptoAction
from dynamodb_encryption_sdk_async.internal.identifiers import ReservedAttributes
from dynamodb_encryption_sdk_async.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk_async.material_providers.static import StaticCryptographicMaterialsProvider
from dynamodb_encryption_sdk_async.material_providers.wrapped import WrappedCryptographicMaterialsProvider
from dynamodb_encryption_sdk_async.materials import CryptographicMaterials
from dynamodb_encryption_sdk_async.materials.raw import RawDecryptionMaterials, RawEncryptionMaterials
from dynamodb_encryption_sdk_async.structures import AttributeActions, EncryptionContext
from dynamodb_encryption_sdk_async.transform import ddb_to_dict, dict_to_ddb

RUNNING_IN_TRAVIS = "TRAVIS" in os.environ
_DELEGATED_KEY_CACHE = defaultdict(lambda: defaultdict(dict))
TEST_TABLE_NAME = "my_table"
TEST_REGION_NAME = "us-west-2"
TEST_INDEX = {
    "partition_attribute": {"type": "S", "value": "test_value"},
    "sort_attribute": {"type": "N", "value": Decimal("99.233")},
}
SECONDARY_INDEX = {
    "secondary_index_1": {"type": "B", "value": Binary(b"\x00\x01\x02")},
    "secondary_index_2": {"type": "S", "value": "another_value"},
}
TEST_KEY = {name: value["value"] for name, value in TEST_INDEX.items()}
TEST_BATCH_INDEXES = [
    {
        "partition_attribute": {"type": "S", "value": "test_value"},
        "sort_attribute": {"type": "N", "value": Decimal("99.233")},
    },
    {
        "partition_attribute": {"type": "S", "value": "test_value"},
        "sort_attribute": {"type": "N", "value": Decimal("92986745")},
    },
    {
        "partition_attribute": {"type": "S", "value": "test_value"},
        "sort_attribute": {"type": "N", "value": Decimal("2231.0001")},
    },
    {
        "partition_attribute": {"type": "S", "value": "another_test_value"},
        "sort_attribute": {"type": "N", "value": Decimal("732342")},
    },
]
TEST_BATCH_KEYS = [{name: value["value"] for name, value in key.items()} for key in TEST_BATCH_INDEXES]


_MOTO_ENVIRONMENT = {
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": TEST_REGION_NAME,
}


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def mock_ddb_service():
    """Centralize service mock to avoid resetting service for tests that use multiple tables.

    moto's in-process mocks patch botocore's HTTP layer, which aiobotocore (aiohttp) does not use,
    so DynamoDB is a moto *server*. ``AWS_ENDPOINT_URL_DYNAMODB`` points every client at it, sync
    (table setup) and async (the code under test) alike.
    """
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=_free_port(), verbose=False)
    server.start()
    host, port = server.get_host_and_port()
    environment = dict(_MOTO_ENVIRONMENT, AWS_ENDPOINT_URL_DYNAMODB="http://{}:{}".format(host, port))
    saved = {name: os.environ.get(name) for name in environment}
    os.environ.update(environment)
    try:
        yield boto3.client("dynamodb", region_name=TEST_REGION_NAME)
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        server.stop()


@pytest.fixture
def example_table(mock_ddb_service):
    mock_ddb_service.create_table(
        TableName=TEST_TABLE_NAME,
        KeySchema=[
            {"AttributeName": "partition_attribute", "KeyType": "HASH"},
            {"AttributeName": "sort_attribute", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": name, "AttributeType": value["type"]} for name, value in TEST_INDEX.items()
        ],
        ProvisionedThroughput={"ReadCapacityUnits": 100, "WriteCapacityUnits": 100},
    )
    yield mock_ddb_service
    mock_ddb_service.delete_table(TableName=TEST_TABLE_NAME)


@pytest.fixture
def table_with_local_secondary_indexes(mock_ddb_service):
    mock_ddb_service.create_table(
        TableName=TEST_TABLE_NAME,
        KeySchema=[
            {"AttributeName": "partition_attribute", "KeyType": "HASH"},
            {"AttributeName": "sort_attribute", "KeyType": "RANGE"},
        ],
        LocalSecondaryIndexes=[
            {
                "IndexName": "lsi-1",
                "KeySchema": [{"AttributeName": "secondary_index_1", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "lsi-2",
                "KeySchema": [{"AttributeName": "secondary_index_2", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        AttributeDefinitions=[
            {"AttributeName": name, "AttributeType": value["type"]}
            for name, value in list(TEST_INDEX.items()) + list(SECONDARY_INDEX.items())
        ],
        ProvisionedThroughput={"ReadCapacityUnits": 100, "WriteCapacityUnits": 100},
    )
    yield mock_ddb_service
    mock_ddb_service.delete_table(TableName=TEST_TABLE_NAME)


@pytest.fixture
def table_with_global_secondary_indexes(mock_ddb_service):
    mock_ddb_service.create_table(
        TableName=TEST_TABLE_NAME,
        KeySchema=[
            {"AttributeName": "partition_attribute", "KeyType": "HASH"},
            {"AttributeName": "sort_attribute", "KeyType": "RANGE"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "gsi-1",
                "KeySchema": [{"AttributeName": "secondary_index_1", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 100, "WriteCapacityUnits": 100},
            },
            {
                "IndexName": "gsi-2",
                "KeySchema": [{"AttributeName": "secondary_index_2", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 100, "WriteCapacityUnits": 100},
            },
        ],
        AttributeDefinitions=[
            {"AttributeName": name, "AttributeType": value["type"]}
            for name, value in list(TEST_INDEX.items()) + list(SECONDARY_INDEX.items())
        ],
        ProvisionedThroughput={"ReadCapacityUnits": 100, "WriteCapacityUnits": 100},
    )
    yield mock_ddb_service
    mock_ddb_service.delete_table(TableName=TEST_TABLE_NAME)


class PassThroughCryptographicMaterialsProviderThatRequiresAttributes(CryptographicMaterialsProvider):
    """Cryptographic materials provider that passes through to another, but requires that attributes are set.

    If the EncryptionContext passed to decryption_materials or encryption_materials
    ever does not have attributes set,
    a ValueError is raised.
    Otherwise, it passes through to the passthrough CMP normally.
    """

    def __init__(self, passthrough_cmp):
        self._passthrough_cmp = passthrough_cmp

    @staticmethod
    def _assert_attributes_set(encryption_context):
        # type: (EncryptionContext) -> None
        if not encryption_context.attributes:
            raise ValueError("Encryption context attributes MUST be set!")

    async def decryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> CryptographicMaterials
        self._assert_attributes_set(encryption_context)
        return await self._passthrough_cmp.decryption_materials(encryption_context)

    async def encryption_materials(self, encryption_context):
        # type: (EncryptionContext) -> CryptographicMaterials
        self._assert_attributes_set(encryption_context)
        return await self._passthrough_cmp.encryption_materials(encryption_context)

    async def refresh(self):
        # type: () -> None
        await self._passthrough_cmp.refresh()


def _get_from_cache(dk_class, algorithm, key_length):
    """Don't generate new keys every time. All we care about is that they are valid keys, not that they are unique."""
    try:
        return _DELEGATED_KEY_CACHE[dk_class][algorithm][key_length]
    except KeyError:
        key = dk_class.generate(algorithm, key_length)
        _DELEGATED_KEY_CACHE[dk_class][algorithm][key_length] = key
        return key


def build_static_jce_cmp(encryption_algorithm, encryption_key_length, signing_algorithm, signing_key_length):
    """Build a StaticCryptographicMaterialsProvider using ephemeral JceNameLocalDelegatedKeys as specified."""
    encryption_key = _get_from_cache(JceNameLocalDelegatedKey, encryption_algorithm, encryption_key_length)
    authentication_key = _get_from_cache(JceNameLocalDelegatedKey, signing_algorithm, signing_key_length)
    encryption_materials = RawEncryptionMaterials(signing_key=authentication_key, encryption_key=encryption_key)
    decryption_materials = RawDecryptionMaterials(verification_key=authentication_key, decryption_key=encryption_key)
    return StaticCryptographicMaterialsProvider(
        encryption_materials=encryption_materials, decryption_materials=decryption_materials
    )


def _build_wrapped_jce_cmp(wrapping_algorithm, wrapping_key_length, signing_algorithm, signing_key_length):
    """Build a WrappedCryptographicMaterialsProvider using ephemeral JceNameLocalDelegatedKeys as specified."""
    wrapping_key = _get_from_cache(JceNameLocalDelegatedKey, wrapping_algorithm, wrapping_key_length)
    signing_key = _get_from_cache(JceNameLocalDelegatedKey, signing_algorithm, signing_key_length)
    return WrappedCryptographicMaterialsProvider(
        wrapping_key=wrapping_key, unwrapping_key=wrapping_key, signing_key=signing_key
    )


def _all_encryption():
    """All encryption configurations to test in slow tests."""
    return itertools.chain(itertools.product(("AES",), (128, 256)), itertools.product(("RSA",), (1024, 2048, 4096)))


def _all_authentication():
    """All authentication configurations to test in slow tests."""
    return itertools.chain(
        itertools.product(("HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512"), (128, 256)),
        itertools.product(("SHA224withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA"), (1024, 2048, 4096)),
    )


def _all_algorithm_pairs():
    """All algorithm pairs (encryption + authentication) to test in slow tests."""
    for encryption_pair, signing_pair in itertools.product(_all_encryption(), _all_authentication()):
        yield encryption_pair + signing_pair


def _some_algorithm_pairs():
    """Cherry-picked set of algorithm pairs (encryption + authentication) to test in fast tests."""
    return (("AES", 256, "HmacSHA256", 256), ("AES", 256, "SHA256withRSA", 4096), ("RSA", 4096, "SHA256withRSA", 4096))


_cmp_builders = {"static": build_static_jce_cmp, "wrapped": _build_wrapped_jce_cmp}


def _all_possible_cmps(algorithm_generator, require_attributes):
    """Generate all possible cryptographic materials providers based on the supplied generator.

    require_attributes determines whether the CMP will be wrapped in
    PassThroughCryptographicMaterialsProviderThatRequiresAttributes
    to require that attributes are set on every request.
    This should ONLY be disabled on the item encryptor tests.
    All high-level helper clients MUST set the attributes before passing the encryption context down.
    """
    # The AES combinations do the same thing, but this makes sure that the AESWrap name works as expected.
    yield _build_wrapped_jce_cmp("AESWrap", 256, "HmacSHA256", 256)

    for builder_info, args in itertools.product(_cmp_builders.items(), algorithm_generator()):
        builder_type, builder_func = builder_info
        encryption_algorithm, encryption_key_length, signing_algorithm, signing_key_length = args

        if builder_type == "static" and encryption_algorithm != "AES":
            # Only AES keys are allowed to be used with static materials
            continue

        id_string = "{enc_algorithm}/{enc_key_length} {builder_type} {sig_algorithm}/{sig_key_length}".format(
            enc_algorithm=encryption_algorithm,
            enc_key_length=encryption_key_length,
            builder_type=builder_type,
            sig_algorithm=signing_algorithm,
            sig_key_length=signing_key_length,
        )

        inner_cmp = builder_func(encryption_algorithm, encryption_key_length, signing_algorithm, signing_key_length)

        if require_attributes:
            outer_cmp = PassThroughCryptographicMaterialsProviderThatRequiresAttributes(inner_cmp)
        else:
            outer_cmp = inner_cmp

        yield pytest.param(outer_cmp, id=id_string)


def set_parametrized_cmp(metafunc, require_attributes=True):
    """Set paramatrized values for cryptographic materials providers.

    require_attributes determines whether the CMP will be wrapped in
    PassThroughCryptographicMaterialsProviderThatRequiresAttributes
    to require that attributes are set on every request.
    This should ONLY be disabled on the item encryptor tests.
    All high-level helper clients MUST set the attributes before passing the encryption context down.
    """
    for name, algorithm_generator in (("all_the_cmps", _all_algorithm_pairs), ("some_cmps", _some_algorithm_pairs)):
        if name in metafunc.fixturenames:
            metafunc.parametrize(name, _all_possible_cmps(algorithm_generator, require_attributes))


_ACTIONS = {
    "hypothesis_actions": (
        pytest.param(AttributeActions(default_action=CryptoAction.ENCRYPT_AND_SIGN), id="encrypt all"),
        pytest.param(AttributeActions(default_action=CryptoAction.SIGN_ONLY), id="sign only all"),
        pytest.param(AttributeActions(default_action=CryptoAction.DO_NOTHING), id="do nothing"),
    )
}
_ACTIONS["parametrized_actions"] = _ACTIONS["hypothesis_actions"] + (
    pytest.param(
        AttributeActions(
            default_action=CryptoAction.ENCRYPT_AND_SIGN,
            attribute_actions={
                "number_set": CryptoAction.SIGN_ONLY,
                "string_set": CryptoAction.SIGN_ONLY,
                "binary_set": CryptoAction.SIGN_ONLY,
            },
        ),
        id="sign sets, encrypt everything else",
    ),
    pytest.param(
        AttributeActions(
            default_action=CryptoAction.ENCRYPT_AND_SIGN,
            attribute_actions={
                "number_set": CryptoAction.DO_NOTHING,
                "string_set": CryptoAction.DO_NOTHING,
                "binary_set": CryptoAction.DO_NOTHING,
            },
        ),
        id="ignore sets, encrypt everything else",
    ),
    pytest.param(
        AttributeActions(
            default_action=CryptoAction.DO_NOTHING, attribute_actions={"map": CryptoAction.ENCRYPT_AND_SIGN}
        ),
        id="encrypt map, ignore everything else",
    ),
    pytest.param(
        AttributeActions(
            default_action=CryptoAction.SIGN_ONLY,
            attribute_actions={
                "number_set": CryptoAction.DO_NOTHING,
                "string_set": CryptoAction.DO_NOTHING,
                "binary_set": CryptoAction.DO_NOTHING,
                "map": CryptoAction.ENCRYPT_AND_SIGN,
            },
        ),
        id="ignore sets, encrypt map, sign everything else",
    ),
)


def set_parametrized_actions(metafunc):
    """Set parametrized values for attribute actions."""
    for name, actions in _ACTIONS.items():
        if name in metafunc.fixturenames:
            metafunc.parametrize(name, actions)


def set_parametrized_item(metafunc):
    """Set parametrized values for items to cycle."""
    if "parametrized_item" in metafunc.fixturenames:
        metafunc.parametrize("parametrized_item", (pytest.param(diverse_item(), id="diverse item"),))


def diverse_item():
    base_item = {
        "int": 5,
        "decimal": Decimal("123.456"),
        "string": "this is a string",
        "binary": b"this is a bytestring! \x01",
        "number_set": set([5, 4, 3]),
        "string_set": set(["abc", "def", "geh"]),
        "binary_set": set([b"\x00\x00\x00", b"\x00\x01\x00", b"\x00\x00\x02"]),
    }
    base_item["list"] = [copy.copy(i) for i in base_item.values()]
    base_item["map"] = copy.deepcopy(base_item)
    return copy.deepcopy(base_item)


_reserved_attributes = {attr.value for attr in ReservedAttributes}


async def return_requestitems_as_unprocessed(*args, **kwargs):
    return {"UnprocessedItems": kwargs["RequestItems"]}


def check_encrypted_item(plaintext_item, ciphertext_item, attribute_actions):
    # Verify that all expected attributes are present
    ciphertext_attributes = set(ciphertext_item.keys())
    plaintext_attributes = set(plaintext_item.keys())
    if attribute_actions.take_no_actions:
        assert ciphertext_attributes == plaintext_attributes
    else:
        assert ciphertext_attributes == plaintext_attributes.union(_reserved_attributes)

    for name, value in ciphertext_item.items():
        # Skip the attributes we add
        if name in _reserved_attributes:
            continue

        # If the attribute should have been encrypted, verify that it is Binary and different from the original
        if attribute_actions.action(name) is CryptoAction.ENCRYPT_AND_SIGN:
            assert isinstance(value, Binary)
            assert value != plaintext_item[name]
        # Otherwise, verify that it is the same as the original
        else:
            assert value == plaintext_item[name]


def _matching_key(actual_item, expected):
    expected_item = [
        i
        for i in expected
        if i["partition_attribute"] == actual_item["partition_attribute"]
        and i["sort_attribute"] == actual_item["sort_attribute"]
    ]
    assert len(expected_item) == 1
    return expected_item[0]


def _nop_transformer(item):
    return item


def assert_items_exist_in_list(source, expected, transformer):
    for actual_item in source:
        expected_item = _matching_key(actual_item, expected)
        assert transformer(actual_item) == transformer(expected_item)


def assert_equal_lists_of_items(actual, expected, transformer=_nop_transformer):
    assert len(actual) == len(expected)
    assert_items_exist_in_list(actual, expected, transformer)


def assert_list_of_items_contains(full, subset, transformer=_nop_transformer):
    assert len(full) >= len(subset)
    assert_items_exist_in_list(subset, full, transformer)


def check_many_encrypted_items(actual, expected, attribute_actions, transformer=_nop_transformer):
    assert len(actual) == len(expected)

    for actual_item in actual:
        expected_item = _matching_key(actual_item, expected)
        check_encrypted_item(
            plaintext_item=transformer(expected_item),
            ciphertext_item=transformer(actual_item),
            attribute_actions=attribute_actions,
        )


def _generate_items(initial_item, write_transformer):
    items = []
    for key in TEST_BATCH_KEYS:
        _item = initial_item.copy()
        _item.update(key)
        items.append(write_transformer(_item))
    return items


async def _cleanup_items(encrypted, write_transformer, table_name=TEST_TABLE_NAME):
    ddb_keys = [write_transformer(key) for key in TEST_BATCH_KEYS]
    _delete_result = await encrypted.batch_write_item(  # noqa
        RequestItems={table_name: [{"DeleteRequest": {"Key": _key}} for _key in ddb_keys]}
    )


async def cycle_batch_item_check(
    raw,
    encrypted,
    initial_actions,
    initial_item,
    write_transformer=_nop_transformer,
    read_transformer=_nop_transformer,
    table_name=TEST_TABLE_NAME,
    delete_items=True,
):
    """Check that cycling (plaintext->encrypted->decrypted) item batch has the expected results."""
    check_attribute_actions = initial_actions.copy()
    check_attribute_actions.set_index_keys(*list(TEST_KEY.keys()))
    items = _generate_items(initial_item, write_transformer)
    items_in_table = len(items)

    _put_result = await encrypted.batch_write_item(  # noqa
        RequestItems={table_name: [{"PutRequest": {"Item": _item}} for _item in items]}
    )

    try:
        ddb_keys = [write_transformer(key) for key in TEST_BATCH_KEYS]
        encrypted_result = await raw.batch_get_item(RequestItems={table_name: {"Keys": ddb_keys}})
        check_many_encrypted_items(
            actual=encrypted_result["Responses"][table_name],
            expected=items,
            attribute_actions=check_attribute_actions,
            transformer=read_transformer,
        )

        decrypted_result = await encrypted.batch_get_item(RequestItems={table_name: {"Keys": ddb_keys}})
        assert_equal_lists_of_items(
            actual=decrypted_result["Responses"][table_name], expected=items, transformer=read_transformer
        )
    finally:
        if delete_items:
            await _cleanup_items(encrypted, write_transformer, table_name)
            items_in_table = 0

    del check_attribute_actions
    del items
    return items_in_table


async def cycle_batch_writer_check(raw_table, encrypted_table, initial_actions, initial_item):
    """Cycling (plaintext->encrypted->decrypted) items with the Table batch writer should have the expected results."""
    check_attribute_actions = initial_actions.copy()
    check_attribute_actions.set_index_keys(*list(TEST_KEY.keys()))
    items = _generate_items(initial_item, _nop_transformer)

    async with encrypted_table.batch_writer() as writer:
        for item in items:
            await writer.put_item(item)

    ddb_keys = copy.copy(TEST_BATCH_KEYS)
    encrypted_items = [(await raw_table.get_item(Key=key, ConsistentRead=True))["Item"] for key in ddb_keys]
    check_many_encrypted_items(
        actual=encrypted_items, expected=items, attribute_actions=check_attribute_actions, transformer=_nop_transformer
    )

    decrypted_result = [(await encrypted_table.get_item(Key=key, ConsistentRead=True))["Item"] for key in ddb_keys]
    assert_equal_lists_of_items(actual=decrypted_result, expected=items, transformer=_nop_transformer)

    async with encrypted_table.batch_writer() as writer:
        for key in ddb_keys:
            await writer.delete_item(key)

    del check_attribute_actions
    del items


async def batch_write_item_unprocessed_check(
    encrypted, initial_item, write_transformer=_nop_transformer, table_name=TEST_TABLE_NAME
):
    """Check that unprocessed items in a batch result are unencrypted."""
    items = _generate_items(initial_item, write_transformer)

    request_items = {table_name: [{"PutRequest": {"Item": _item}} for _item in items]}
    _put_result = await encrypted.batch_write_item(RequestItems=request_items)

    # we expect results to include Unprocessed items, or the test case is invalid!
    unprocessed_items = _put_result["UnprocessedItems"]
    assert unprocessed_items != {}

    unprocessed = [operation["PutRequest"]["Item"] for operation in unprocessed_items[TEST_TABLE_NAME]]
    assert_list_of_items_contains(items, unprocessed, transformer=_nop_transformer)

    del items


async def cycle_item_check(plaintext_item, crypto_config):
    """Check that cycling (plaintext->encrypted->decrypted) an item has the expected results."""
    ciphertext_item = await encrypt_python_item(plaintext_item, crypto_config)

    check_encrypted_item(plaintext_item, ciphertext_item, crypto_config.attribute_actions)

    cycled_item = await decrypt_python_item(ciphertext_item, crypto_config)

    assert cycled_item == plaintext_item
    del ciphertext_item
    del cycled_item


def _session():
    return aioboto3.Session()


def _client_kwargs(region_name):
    return {} if region_name is None else {"region_name": region_name}


async def table_cycle_check(materials_provider, initial_actions, initial_item, table_name, region_name=None):
    check_attribute_actions = initial_actions.copy()
    check_attribute_actions.set_index_keys(*list(TEST_KEY.keys()))
    item = initial_item.copy()
    item.update(TEST_KEY)

    async with _session().resource("dynamodb", **_client_kwargs(region_name)) as resource:
        table = await resource.Table(table_name)
        e_table = EncryptedTable(table=table, materials_provider=materials_provider, attribute_actions=initial_actions)

        _put_result = await e_table.put_item(Item=item)  # noqa

        encrypted_result = await table.get_item(Key=TEST_KEY, ConsistentRead=True)
        check_encrypted_item(item, encrypted_result["Item"], check_attribute_actions)

        decrypted_result = await e_table.get_item(Key=TEST_KEY, ConsistentRead=True)
        assert decrypted_result["Item"] == item

        await e_table.delete_item(Key=TEST_KEY)
    del item
    del check_attribute_actions


async def table_cycle_batch_writer_check(
    materials_provider, initial_actions, initial_item, table_name, region_name=None
):
    async with _session().resource("dynamodb", **_client_kwargs(region_name)) as resource:
        table = await resource.Table(table_name)
        e_table = EncryptedTable(table=table, materials_provider=materials_provider, attribute_actions=initial_actions)

        await cycle_batch_writer_check(table, e_table, initial_actions, initial_item)


async def table_batch_writer_unprocessed_items_check(
    materials_provider, initial_actions, initial_item, table_name, region_name=None
):
    async with _session().resource("dynamodb", **_client_kwargs(region_name)) as resource:
        table = await resource.Table(table_name)

        items = _generate_items(initial_item, _nop_transformer)
        request_items = {table_name: [{"PutRequest": {"Item": _item}} for _item in items]}

        with patch.object(table.meta.client, "batch_write_item", new_callable=AsyncMock) as batch_write_mock:
            # Check that unprocessed items returned to a BatchWriter are successfully retried
            batch_write_mock.side_effect = [{"UnprocessedItems": request_items}, {"UnprocessedItems": {}}]
            e_table = EncryptedTable(
                table=table, materials_provider=materials_provider, attribute_actions=initial_actions
            )

            async with e_table.batch_writer() as writer:
                for item in items:
                    await writer.put_item(item)

    del items


async def resource_cycle_batch_items_check(
    materials_provider, initial_actions, initial_item, table_name, region_name=None
):
    async with _session().resource("dynamodb", **_client_kwargs(region_name)) as resource:
        e_resource = EncryptedResource(
            resource=resource, materials_provider=materials_provider, attribute_actions=initial_actions
        )

        await cycle_batch_item_check(
            raw=resource,
            encrypted=e_resource,
            initial_actions=initial_actions,
            initial_item=initial_item,
            table_name=table_name,
        )

        raw_scan_result = await (await resource.Table(table_name)).scan(ConsistentRead=True)
        e_scan_result = await (await e_resource.Table(table_name)).scan(ConsistentRead=True)
        assert not raw_scan_result["Items"]
        assert not e_scan_result["Items"]


async def resource_batch_items_unprocessed_check(
    materials_provider, initial_actions, initial_item, table_name, region_name=None
):
    async with _session().resource("dynamodb", **_client_kwargs(region_name)) as resource:
        with patch.object(resource, "batch_write_item", return_requestitems_as_unprocessed):
            e_resource = EncryptedResource(
                resource=resource, materials_provider=materials_provider, attribute_actions=initial_actions
            )

            await batch_write_item_unprocessed_check(
                encrypted=e_resource, initial_item=initial_item, write_transformer=dict_to_ddb, table_name=table_name
            )


async def client_cycle_single_item_check(
    materials_provider, initial_actions, initial_item, table_name, region_name=None
):
    check_attribute_actions = initial_actions.copy()
    check_attribute_actions.set_index_keys(*list(TEST_KEY.keys()))
    item = initial_item.copy()
    item.update(TEST_KEY)
    ddb_item = dict_to_ddb(item)
    ddb_key = dict_to_ddb(TEST_KEY)

    async with _session().client("dynamodb", **_client_kwargs(region_name)) as client:
        e_client = EncryptedClient(
            client=client, materials_provider=materials_provider, attribute_actions=initial_actions
        )

        _put_result = await e_client.put_item(TableName=table_name, Item=ddb_item)  # noqa

        encrypted_result = await client.get_item(TableName=table_name, Key=ddb_key, ConsistentRead=True)
        check_encrypted_item(item, ddb_to_dict(encrypted_result["Item"]), check_attribute_actions)

        decrypted_result = await e_client.get_item(TableName=table_name, Key=ddb_key, ConsistentRead=True)
        assert ddb_to_dict(decrypted_result["Item"]) == item

        await e_client.delete_item(TableName=table_name, Key=ddb_key)
    del item
    del check_attribute_actions


async def client_cycle_batch_items_check(
    materials_provider, initial_actions, initial_item, table_name, region_name=None
):
    async with _session().client("dynamodb", **_client_kwargs(region_name)) as client:
        e_client = EncryptedClient(
            client=client, materials_provider=materials_provider, attribute_actions=initial_actions
        )

        await cycle_batch_item_check(
            raw=client,
            encrypted=e_client,
            initial_actions=initial_actions,
            initial_item=initial_item,
            write_transformer=dict_to_ddb,
            read_transformer=ddb_to_dict,
            table_name=table_name,
        )

        raw_scan_result = await client.scan(TableName=table_name, ConsistentRead=True)
        e_scan_result = await e_client.scan(TableName=table_name, ConsistentRead=True)
        assert not raw_scan_result["Items"]
        assert not e_scan_result["Items"]


async def client_batch_items_unprocessed_check(
    materials_provider, initial_actions, initial_item, table_name, region_name=None
):
    async with _session().client("dynamodb", **_client_kwargs(region_name)) as client:
        with patch.object(client, "batch_write_item", return_requestitems_as_unprocessed):
            e_client = EncryptedClient(
                client=client, materials_provider=materials_provider, attribute_actions=initial_actions
            )

            await batch_write_item_unprocessed_check(
                encrypted=e_client, initial_item=initial_item, write_transformer=dict_to_ddb, table_name=table_name
            )


async def client_cycle_batch_items_check_scan_paginator(
    materials_provider, initial_actions, initial_item, table_name, region_name=None
):
    """Helper function for testing the "scan" paginator.

    Populate the specified table with encrypted items,
    scan the table with raw client paginator to get encrypted items,
    scan the table with encrypted client paginator to get decrypted items,
    then verify that all items appear to have been encrypted correctly.
    """  # noqa=D401
    # pylint: disable=too-many-locals
    async with _session().client("dynamodb", **_client_kwargs(region_name)) as client:
        e_client = EncryptedClient(
            client=client, materials_provider=materials_provider, attribute_actions=initial_actions
        )

        items_in_table = await cycle_batch_item_check(
            raw=client,
            encrypted=e_client,
            initial_actions=initial_actions,
            initial_item=initial_item,
            write_transformer=dict_to_ddb,
            read_transformer=ddb_to_dict,
            table_name=table_name,
            delete_items=False,
        )

        try:
            encrypted_items = []
            raw_paginator = client.get_paginator("scan")
            async for page in raw_paginator.paginate(TableName=table_name, ConsistentRead=True):
                encrypted_items.extend(page["Items"])

            decrypted_items = []
            encrypted_paginator = e_client.get_paginator("scan")
            async for page in encrypted_paginator.paginate(TableName=table_name, ConsistentRead=True):
                decrypted_items.extend(page["Items"])

            assert encrypted_items and decrypted_items
            assert len(encrypted_items) == len(decrypted_items) == items_in_table

            check_attribute_actions = initial_actions.copy()
            check_attribute_actions.set_index_keys(*list(TEST_KEY.keys()))
            check_many_encrypted_items(
                actual=encrypted_items,
                expected=decrypted_items,
                attribute_actions=check_attribute_actions,
                transformer=ddb_to_dict,
            )

        finally:
            await _cleanup_items(encrypted=e_client, write_transformer=dict_to_ddb, table_name=table_name)

        raw_scan_result = await client.scan(TableName=table_name, ConsistentRead=True)
        e_scan_result = await e_client.scan(TableName=table_name, ConsistentRead=True)
        assert not raw_scan_result["Items"]
        assert not e_scan_result["Items"]
