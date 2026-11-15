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
"""Otherwise undifferentiated utility resources.

.. warning::
    No guarantee is provided on the modules and APIs within this
    namespace staying consistent. Directly reference at your own risk.
"""
import asyncio
import copy
import inspect
from functools import partial
from typing import Any, AsyncIterator, Callable, Dict, Iterable, Text

import attr
from aiobotocore.client import AioBaseClient

from dynamodb_encryption_sdk_async.encrypted import CryptoConfig
from dynamodb_encryption_sdk_async.encrypted.item import decrypt_python_item, encrypt_python_item
from dynamodb_encryption_sdk_async.exceptions import InvalidArgumentError
from dynamodb_encryption_sdk_async.structures import CryptoAction, EncryptionContext, TableInfo
from dynamodb_encryption_sdk_async.transform import dict_to_ddb

__all__ = (
    "TableInfoCache",
    "crypto_config_from_kwargs",
    "crypto_config_from_table_info",
    "crypto_config_from_cache",
    "decrypt_get_item",
    "decrypt_multi_get",
    "decrypt_list_of_items",
    "decrypt_batch_get_item",
    "encrypt_put_item",
    "encrypt_batch_write_item",
    "validate_get_arguments",
)


@attr.s(init=False)
class TableInfoCache(object):
    # pylint: disable=too-few-public-methods
    """Very simple cache of TableInfo objects, providing configuration information about DynamoDB tables.

    :param client: aiobotocore DynamoDB client
    :type client: aiobotocore.client.AioBaseClient
    :param bool auto_refresh_table_indexes: Should we attempt to refresh information about table indexes?
        Requires ``dynamodb:DescribeTable`` permissions on each table.
    """

    _client = attr.ib(validator=attr.validators.instance_of(AioBaseClient))
    _auto_refresh_table_indexes = attr.ib(validator=attr.validators.instance_of(bool))

    def __init__(self, client, auto_refresh_table_indexes):  # noqa=D107
        # type: (AioBaseClient, bool) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self._client = client
        self._auto_refresh_table_indexes = auto_refresh_table_indexes
        attr.validate(self)
        self.__attrs_post_init__()

    def __attrs_post_init__(self):
        """Set up the empty cache."""
        self._all_tables_info = {}  # type: Dict[Text, TableInfo]  # pylint: disable=attribute-defined-outside-init
        # In-flight loads, so concurrent first lookups of a table share one DescribeTable.
        # The futures belong to the running event loop: use a cache from one loop only.
        self._pending = {}  # type: Dict[Text, asyncio.Future]  # pylint: disable=attribute-defined-outside-init

    async def table_info(self, table_name):
        """Collect a TableInfo object for the specified table, creating and adding it to
        the cache if not already present.

        :param str table_name: Name of table
        :returns: TableInfo describing the requested table
        :rtype: TableInfo
        """
        try:
            return self._all_tables_info[table_name]
        except KeyError:
            pass
        pending = self._pending.get(table_name)
        if pending is None:
            pending = asyncio.ensure_future(self._load_table_info(table_name))
            self._pending[table_name] = pending
        # Shield: one waiter being cancelled must not cancel the load the others wait on.
        return await asyncio.shield(pending)

    async def _load_table_info(self, table_name):
        try:
            _table_info = TableInfo(name=table_name)
            if self._auto_refresh_table_indexes:
                await _table_info.refresh_indexed_attributes(self._client)
            self._all_tables_info[table_name] = _table_info
            return _table_info
        finally:
            self._pending.pop(table_name, None)


def validate_get_arguments(kwargs):
    # type: (Dict[Text, Any]) -> None
    """Verify that attribute filtering parameters are not found in the request.

    :raises InvalidArgumentError: if banned parameters are found
    """
    for arg in ("AttributesToGet", "ProjectionExpression"):
        if arg in kwargs:
            raise InvalidArgumentError('"{}" is not supported for this operation'.format(arg))

    if kwargs.get("Select", None) in ("SPECIFIC_ATTRIBUTES", "ALL_PROJECTED_ATTRIBUTES"):
        raise InvalidArgumentError('Scan "Select" value of "{}" is not supported'.format(kwargs["Select"]))


async def crypto_config_from_kwargs(fallback, **kwargs):
    """Pull all encryption-specific parameters from the request and use them to build a crypto config.

    :returns: crypto config and updated kwargs
    :rtype: dynamodb_encryption_sdk_async.encrypted.CryptoConfig and dict
    """
    try:
        crypto_config = kwargs.pop("crypto_config")
    except KeyError:
        try:
            fallback_kwargs = {"table_name": kwargs["TableName"]}
        except KeyError:
            fallback_kwargs = {}
        crypto_config = fallback(**fallback_kwargs)
        if inspect.isawaitable(crypto_config):
            crypto_config = await crypto_config
    return crypto_config, kwargs


def crypto_config_from_table_info(materials_provider, attribute_actions, table_info):
    """Build a crypto config from the provided values and table info.

    :returns: crypto config and updated kwargs
    :rtype: tuple(CryptoConfig, dict)
    """
    ec_kwargs = table_info.encryption_context_values
    if table_info.primary_index is not None:
        ec_kwargs.update(
            {"partition_key_name": table_info.primary_index.partition, "sort_key_name": table_info.primary_index.sort}
        )

    return CryptoConfig(
        materials_provider=materials_provider,
        encryption_context=EncryptionContext(**ec_kwargs),
        attribute_actions=attribute_actions,
    )


async def crypto_config_from_cache(materials_provider, attribute_actions, table_info_cache, table_name):
    """Build a crypto config from the provided values, loading the table info from the provided cache.

    :returns: crypto config and updated kwargs
    :rtype: tuple(CryptoConfig, dict)
    """
    table_info = await table_info_cache.table_info(table_name)

    attribute_actions = attribute_actions.copy()
    attribute_actions.set_index_keys(*table_info.protected_index_keys())

    return crypto_config_from_table_info(materials_provider, attribute_actions, table_info)


def _item_transformer(crypto_transformer):
    """Supply an item transformer to go from an item that the provided ``crypto_transformer``
    can understand to a DynamoDB JSON object.

    :param crypto_transformer: An item encryptor or decryptor function
    :returns: Item transformer function
    """
    if crypto_transformer in (decrypt_python_item, encrypt_python_item):
        return dict_to_ddb

    return lambda x: x


async def decrypt_list_of_items(crypto_config, decrypt_method, items):
    # type: (CryptoConfig, Callable, Iterable[Any]) -> AsyncIterator[Any]
    # narrow this down
    # https://github.com/aws/aws-dynamodb-encryption-python/issues/66
    """Iterate through a list of encrypted items, decrypting each item and yielding the plaintext item.

    :param CryptoConfig crypto_config: :class:`CryptoConfig` to use
    :param callable decrypt_method: Method to use to decrypt items
    :param items: Iterable of encrypted items
    :return: Async iterator of plaintext items
    """
    for value in items:
        yield await decrypt_method(
            item=value, crypto_config=crypto_config.with_item(_item_transformer(decrypt_method)(value))
        )


async def decrypt_multi_get(decrypt_method, crypto_config_method, read_method, **kwargs):
    # type: (Callable, Callable, Callable, **Any) -> Dict
    # narrow this down
    # https://github.com/aws/aws-dynamodb-encryption-python/issues/66
    """Transparently decrypt multiple items after getting them from the table with a scan or query method.

    :param callable decrypt_method: Method to use to decrypt items
    :param callable crypto_config_method: Method that accepts ``kwargs`` and provides a :class:`CryptoConfig`
    :param callable read_method: Method that reads from the table
    :param ``**kwargs``: Keyword arguments to pass to ``read_method``
    :return: DynamoDB response
    :rtype: dict
    """
    validate_get_arguments(kwargs)
    crypto_config, ddb_kwargs = await crypto_config_method(**kwargs)
    response = await read_method(**ddb_kwargs)
    response["Items"] = [
        item
        async for item in decrypt_list_of_items(
            crypto_config=crypto_config, decrypt_method=decrypt_method, items=response["Items"]
        )
    ]
    return response


async def decrypt_get_item(decrypt_method, crypto_config_method, read_method, **kwargs):
    # type: (Callable, Callable, Callable, **Any) -> Dict
    # narrow this down
    # https://github.com/aws/aws-dynamodb-encryption-python/issues/66
    """Transparently decrypt an item after getting it from the table.

    :param callable decrypt_method: Method to use to decrypt item
    :param callable crypto_config_method: Method that accepts ``kwargs`` and provides a :class:`CryptoConfig`
    :param callable read_method: Method that reads from the table
    :param ``**kwargs``: Keyword arguments to pass to ``read_method``
    :return: DynamoDB response
    :rtype: dict
    """
    validate_get_arguments(kwargs)
    crypto_config, ddb_kwargs = await crypto_config_method(**kwargs)
    response = await read_method(**ddb_kwargs)
    if "Item" in response:
        response["Item"] = await decrypt_method(
            item=response["Item"],
            crypto_config=crypto_config.with_item(_item_transformer(decrypt_method)(response["Item"])),
        )
    return response


async def decrypt_batch_get_item(decrypt_method, crypto_config_method, read_method, **kwargs):
    # type: (Callable, Callable, Callable, **Any) -> Dict
    # narrow this down
    # https://github.com/aws/aws-dynamodb-encryption-python/issues/66
    """Transparently decrypt multiple items after getting them in a batch request.

    :param callable decrypt_method: Method to use to decrypt items
    :param callable crypto_config_method: Method that accepts ``kwargs`` and provides a :class:`CryptoConfig`
    :param callable read_method: Method that reads from the table
    :param ``**kwargs``: Keyword arguments to pass to ``read_method``
    :return: DynamoDB response
    :rtype: dict
    """
    request_crypto_config = kwargs.pop("crypto_config", None)

    for _table_name, table_kwargs in kwargs["RequestItems"].items():
        validate_get_arguments(table_kwargs)

    response = await read_method(**kwargs)
    for table_name, items in response["Responses"].items():
        if request_crypto_config is not None:
            crypto_config = request_crypto_config
        else:
            crypto_config = await crypto_config_method(table_name=table_name)

        for pos, value in enumerate(items):
            items[pos] = await decrypt_method(
                item=value, crypto_config=crypto_config.with_item(_item_transformer(decrypt_method)(items[pos]))
            )
    return response


async def encrypt_put_item(encrypt_method, crypto_config_method, write_method, **kwargs):
    # type: (Callable, Callable, Callable, **Any) -> Dict
    # narrow this down
    # https://github.com/aws/aws-dynamodb-encryption-python/issues/66
    """Transparently encrypt an item before putting it to the table.

    :param callable encrypt_method: Method to use to encrypt items
    :param callable crypto_config_method: Method that accepts ``kwargs`` and provides a :class:`CryptoConfig`
    :param callable write_method: Method that writes to the table
    :param ``**kwargs``: Keyword arguments to pass to ``write_method``
    :return: DynamoDB response
    :rtype: dict
    """
    crypto_config, ddb_kwargs = await crypto_config_method(**kwargs)
    ddb_kwargs["Item"] = await encrypt_method(
        item=ddb_kwargs["Item"],
        crypto_config=crypto_config.with_item(_item_transformer(encrypt_method)(ddb_kwargs["Item"])),
    )
    return await write_method(**ddb_kwargs)


async def encrypt_batch_write_item(encrypt_method, crypto_config_method, write_method, **kwargs):
    # type: (Callable, Callable, Callable, **Any) -> Dict
    # narrow this down
    # https://github.com/aws/aws-dynamodb-encryption-python/issues/66
    """Transparently encrypt multiple items before putting them in a batch request.

    :param callable encrypt_method: Method to use to encrypt items
    :param callable crypto_config_method: Method that accepts a table name string and provides a :class:`CryptoConfig`
    :param callable write_method: Method that writes to the table
    :param ``**kwargs``: Keyword arguments to pass to ``write_method``
    :return: DynamoDB response
    :rtype: dict
    """
    request_crypto_config = kwargs.pop("crypto_config", None)
    table_crypto_configs = {}
    plaintext_items = copy.deepcopy(kwargs["RequestItems"])

    for table_name, items in kwargs["RequestItems"].items():
        if request_crypto_config is not None:
            crypto_config = request_crypto_config
        else:
            crypto_config = await crypto_config_method(table_name=table_name)
        table_crypto_configs[table_name] = crypto_config

        for pos, value in enumerate(items):
            for request_type, item in value.items():
                # We don't encrypt primary indexes, so we can ignore DeleteItem requests
                if request_type == "PutRequest":
                    items[pos][request_type]["Item"] = await encrypt_method(
                        item=item["Item"],
                        crypto_config=crypto_config.with_item(_item_transformer(encrypt_method)(item["Item"])),
                    )

    response = await write_method(**kwargs)
    return _process_batch_write_response(plaintext_items, response, table_crypto_configs)


def _process_batch_write_response(request, response, table_crypto_config):
    # type: (Dict, Dict, Dict[Text, CryptoConfig]) -> Dict
    """Handle unprocessed items in the response from a transparently encrypted write.

    :param dict request: The DynamoDB plaintext request dictionary
    :param dict response: The DynamoDB response from the batch operation
    :param Dict[Text, CryptoConfig] table_crypto_config: table level CryptoConfig used in encrypting the request items
    :return: DynamoDB response, with any unprocessed items reverted back to the original plaintext values
    :rtype: dict
    """
    try:
        unprocessed_items = response["UnprocessedItems"]
    except KeyError:
        return response

    # Unprocessed items need to be returned in their original state
    for table_name, unprocessed in unprocessed_items.items():
        original_items = request[table_name]
        crypto_config = table_crypto_config[table_name]

        if crypto_config.encryption_context.partition_key_name:
            items_match = partial(_item_keys_match, crypto_config)
        else:
            items_match = partial(_item_attributes_match, crypto_config)

        for pos, operation in enumerate(unprocessed):
            for request_type, item in operation.items():
                if request_type != "PutRequest":
                    continue

                for plaintext_item in original_items:
                    if plaintext_item.get(request_type) and items_match(
                        plaintext_item[request_type]["Item"], item["Item"]
                    ):
                        unprocessed[pos] = plaintext_item.copy()
                        break

    return response


def _item_keys_match(crypto_config, item1, item2):
    # type: (CryptoConfig, Dict, Dict) -> bool
    """Determines whether the values in the primary and sort keys (if they exist) are the same

    :param CryptoConfig crypto_config: CryptoConfig used in encrypting the given items
    :param dict item1: The first item to compare
    :param dict item2: The second item to compare
    :return: Bool response, True if the key attributes match
    :rtype: bool
    """
    partition_key_name = crypto_config.encryption_context.partition_key_name
    sort_key_name = crypto_config.encryption_context.sort_key_name

    partition_keys_match = item1[partition_key_name] == item2[partition_key_name]

    if sort_key_name is None:
        return partition_keys_match

    return partition_keys_match and item1[sort_key_name] == item2[sort_key_name]


def _item_attributes_match(crypto_config, plaintext_item, encrypted_item):
    # type: (CryptoConfig, Dict, Dict) -> bool
    """Determines whether the unencrypted values in the plaintext items attributes are the same as those in the
    encrypted item. Essentially this uses brute force to cover when we don't know the primary and sort
    index attribute names, since they can't be encrypted.

    :param CryptoConfig crypto_config: CryptoConfig used in encrypting the given items
    :param dict plaintext_item: The plaintext item
    :param dict encrypted_item: The encrypted item
    :return: Bool response, True if the unencrypted attributes in the plaintext item match those in
    the encrypted item
    :rtype: bool
    """

    for name, value in plaintext_item.items():
        if crypto_config.attribute_actions.action(name) == CryptoAction.ENCRYPT_AND_SIGN:
            continue

        if encrypted_item.get(name) != value:
            return False

    return True
