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
"""High-level helper class to provide a familiar interface to encrypted tables."""
import asyncio
from functools import partial
from typing import Optional

import attr
from aioboto3.dynamodb.table import BatchWriter
from boto3.resources.base import ServiceResource

from dynamodb_encryption_sdk.internal.utils import (
    crypto_config_from_kwargs,
    crypto_config_from_table_info,
    decrypt_get_item,
    decrypt_multi_get,
    encrypt_put_item,
)
from dynamodb_encryption_sdk.material_providers import CryptographicMaterialsProvider
from dynamodb_encryption_sdk.structures import AttributeActions, TableInfo

from .client import EncryptedClient
from .item import decrypt_python_item, encrypt_python_item

__all__ = ("EncryptedTable",)


@attr.s(init=False)
class EncryptedTable(object):
    # pylint: disable=too-few-public-methods,too-many-instance-attributes
    """High-level helper class to provide a familiar interface to encrypted tables.

    >>> import aioboto3
    >>> from dynamodb_encryption_sdk.encrypted.table import EncryptedTable
    >>> from dynamodb_encryption_sdk.material_providers.wrapped import WrappedCryptographicMaterialsProvider
    >>> wrapped_cmp = WrappedCryptographicMaterialsProvider(signing_key, wrapping_key, unwrapping_key)
    >>> async with aioboto3.Session().resource('dynamodb') as resource:
    ...     table = await resource.Table('my_table')
    ...     encrypted_table = EncryptedTable(table=table, materials_provider=wrapped_cmp)
    ...     await encrypted_table.put_item(Item=item)

    .. note::

        This class provides a superset of the aioboto3 DynamoDB Table API, so should work as
        a drop-in replacement once configured. Every operation it overrides is a coroutine.

        ``DescribeTable`` cannot run in ``__init__``, so the table's indexes are loaded on the
        first operation (once, even under concurrent use), or eagerly with
        :meth:`refresh_table_info`.

        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/table/index.html#DynamoDB.Table

        If you want to provide per-request cryptographic details, the ``put_item``, ``get_item``,
        ``query``, and ``scan`` methods will also accept a ``crypto_config`` parameter, defining
        a custom :class:`CryptoConfig` instance for this request.

    .. warning::

        We do not currently support the ``update_item`` method.

    :param table: Pre-configured boto3 DynamoDB Table object
    :type table: boto3.resources.base.ServiceResource
    :param CryptographicMaterialsProvider materials_provider: Cryptographic materials provider
        to use
    :param TableInfo table_info: Information about the target DynamoDB table
    :param AttributeActions attribute_actions: Table-level configuration of how to encrypt/sign
        attributes
    :param bool auto_refresh_table_indexes: Should we attempt to refresh information about table indexes?
        Requires ``dynamodb:DescribeTable`` permissions on each table. (default: True)
    """

    _table = attr.ib(validator=attr.validators.instance_of(ServiceResource))
    _materials_provider = attr.ib(validator=attr.validators.instance_of(CryptographicMaterialsProvider))
    _table_info = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(TableInfo)), default=None)
    _attribute_actions = attr.ib(
        validator=attr.validators.instance_of(AttributeActions), default=attr.Factory(AttributeActions)
    )
    _auto_refresh_table_indexes = attr.ib(validator=attr.validators.instance_of(bool), default=True)

    def __init__(
        self,
        table,  # type: ServiceResource
        materials_provider,  # type: CryptographicMaterialsProvider
        table_info=None,  # type: Optional[TableInfo]
        attribute_actions=None,  # type: Optional[AttributeActions]
        auto_refresh_table_indexes=True,  # type: Optional[bool]
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        if attribute_actions is None:
            attribute_actions = AttributeActions()

        self._table = table
        self._materials_provider = materials_provider
        self._table_info = table_info
        self._attribute_actions = attribute_actions
        self._auto_refresh_table_indexes = auto_refresh_table_indexes
        attr.validate(self)
        self.__attrs_post_init__()

    def __attrs_post_init__(self):
        """Set up translation methods; table info is prepared on first use (see :meth:`refresh_table_info`)."""
        self._table_info_ready = False  # attrs confuses pylint: disable=attribute-defined-outside-init
        self._table_info_lock = asyncio.Lock()  # attrs confuses pylint: disable=attribute-defined-outside-init
        # Clone the attribute actions before we modify them
        self._attribute_actions = self._attribute_actions.copy()

        self._crypto_config = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            crypto_config_from_kwargs, self._table_crypto_config
        )
        self.get_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_get_item, decrypt_python_item, self._crypto_config, self._table.get_item
        )
        self.put_item = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            encrypt_put_item, encrypt_python_item, self._crypto_config, self._table.put_item
        )
        self.query = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_multi_get, decrypt_python_item, self._crypto_config, self._table.query
        )
        self.scan = partial(  # attrs confuses pylint: disable=attribute-defined-outside-init
            decrypt_multi_get, decrypt_python_item, self._crypto_config, self._table.scan
        )

    async def refresh_table_info(self):
        """Prepare table info if it was not set, refresh its indexes if configured to, and protect the index keys.

        Upstream does this in ``__init__``; here it runs once, on the first operation, unless called earlier.
        """
        if self._table_info_ready:
            return
        async with self._table_info_lock:
            if self._table_info_ready:
                return
            if self._table_info is None:
                self._table_info = TableInfo(  # attrs confuses pylint: disable=attribute-defined-outside-init
                    name=self._table.name
                )

            if self._auto_refresh_table_indexes:
                await self._table_info.refresh_indexed_attributes(self._table.meta.client)

            self._attribute_actions.set_index_keys(*self._table_info.protected_index_keys())
            self._table_info_ready = True  # attrs confuses pylint: disable=attribute-defined-outside-init

    async def _table_crypto_config(self, **_kwargs):
        await self.refresh_table_info()
        return crypto_config_from_table_info(self._materials_provider, self._attribute_actions, self._table_info)

    def __getattr__(self, name):
        """Catch any method/attribute lookups that are not defined in this class and try
        to find them on the provided bridge object.

        :param str name: Attribute name
        :returns: Result of asking the provided table object for that attribute name
        :raises AttributeError: if attribute is not found on provided bridge object
        """
        return getattr(self._table, name)

    def update_item(self, **kwargs):
        """Update item is not yet supported."""
        raise NotImplementedError('"update_item" is not yet implemented')

    def batch_writer(self, overwrite_by_pkeys=None, flush_amount=25, on_exit_loop_sleep=0):
        """Create an async batch writer object (aioboto3's), which encrypts each item it writes.

        >>> async with encrypted_table.batch_writer() as writer:
        ...     await writer.put_item(Item=item)

        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/table/batch_writer.html

        :type overwrite_by_pkeys: list(string)
        :param overwrite_by_pkeys: De-duplicate request items in buffer if match new request
            item on specified primary keys. i.e ``["partition_key1", "sort_key2", "sort_key3"]``
        """
        encrypted_client = EncryptedClient(
            client=self._table.meta.client,
            materials_provider=self._materials_provider,
            attribute_actions=self._attribute_actions,
            auto_refresh_table_indexes=self._auto_refresh_table_indexes,
            expect_standard_dictionaries=True,
        )
        return BatchWriter(
            table_name=self._table.name,
            client=encrypted_client,
            flush_amount=flush_amount,
            overwrite_by_pkeys=overwrite_by_pkeys,
            on_exit_loop_sleep=on_exit_loop_sleep,
        )
