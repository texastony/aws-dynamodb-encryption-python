# Async conversion

This branch converts the DynamoDB Encryption Client to `asyncio`, on aioboto3 and aiobotocore.
It is based on `fbdf529` (v3.3.0) and was written to answer Question 2 of a proof of concept:
can the DDBEC for Python be made async, assuming no KMS calls?

## Package name

The last commit renames the package to **`dynamodb_encryption_sdk_async`** (distribution
`dynamodb-encryption-sdk-async`), so it can be installed alongside the synchronous PyPI
`dynamodb-encryption-sdk`. To review the async conversion as an in-place diff against upstream,
read the commits before the rename. The tables below use the original module names.

## Before the conversion

These preparatory changes are in a separate commit:
- **Dropped:** `material_providers/aws_kms.py` (no KMS), `material_providers/most_recent.py`, and
  `material_providers/store/` (MetaStore).
- **`six` removed.**

## The async conversion
The boundary is I/O. DynamoDB calls are awaited, and so are the materials provider (CMP) methods, because a CMP may do I/O (Question 3's will). Serialization, encryption, signing and verification stay synchronous; they are CPU work and run on the event loop.

| Upstream (sync) | Fork |
| --- | --- |
| `CryptographicMaterialsProvider.encryption_materials` / `decryption_materials` / `refresh` | `async def`. `Static` and `Wrapped` are trivially async. |
| `CryptoConfig.encryption_materials()` / `decryption_materials()` | `async def` |
| `encrypt_dynamodb_item`, `decrypt_dynamodb_item`, `encrypt_python_item`, `decrypt_python_item` | `async def`. The only `await` is the materials call; the crypto between them is upstream's, unchanged. |
| `TableInfo.refresh_indexed_attributes(client)` | `async def`; awaits `describe_table` on an aiobotocore client |
| `TableInfoCache.table_info` | `async def`. Concurrent first lookups of a table share one `DescribeTable` through a per-table future, shielded so one cancelled caller doesn't cancel the others. Futures are per event loop. |
| `crypto_config_from_kwargs`, `crypto_config_from_cache` | `async def`. `from_kwargs` awaits its fallback if it returns an awaitable. |
| `decrypt_get_item`, `decrypt_multi_get`, `decrypt_batch_get_item`, `encrypt_put_item`, `encrypt_batch_write_item` | `async def`; they await the read or write method |
| `decrypt_list_of_items` | An async generator |
| `EncryptedPaginator.paginate` | An async generator over aiobotocore's async page iterator |
| `EncryptedClient(client=...)` | Requires an `aiobotocore.client.AioBaseClient` |
| `EncryptedTable(table=...)` | Wraps an aioboto3 Table. Upstream calls `DescribeTable` in `__init__`; the fork runs it once, on the first operation, behind an `asyncio.Lock`, or earlier with `await refresh_table_info()`. |
| `EncryptedTable.batch_writer()` | aioboto3's async `BatchWriter`, used with `async with` and `await writer.put_item(...)`, over an `EncryptedClient` (as upstream does with boto3's) |
| `EncryptedResource.Table(name)` | `async def`, as aioboto3's `resource.Table` is |
| `EncryptedTablesCollectionManager.all/filter/limit/page_size` | Async iterators over aioboto3's async collections |

## Unchanged
- `_process_batch_write_response`, which restores plaintext for `UnprocessedItems`.
- `update_item`, which still raises `NotImplementedError`.
- The `__getattr__` pass-throughs.
