#########################################
AWS DynamoDB Encryption Client Examples
#########################################

This section features examples that show you
how to use the AWS DynamoDB Encryption Client.
We demonstrate how to use the encryption and decryption APIs
and how to set up some common configuration patterns.

APIs
====

The AWS DynamoDB Encryption Client provides four high-level APIs: `EncryptedClient`, `EncryptedItem`,
`EncryptedResource`, and `EncryptedTable`.

On this branch every operation is a coroutine, on aioboto3 (see ``ASYNC.md`` at the repository root).
The AWS KMS and MetaStore (``CachingMostRecentProvider``) providers, and their examples, are not on this branch.

Material Providers
==================

To use the encryption and decryption APIs, you need to describe how you want the library to protect your data keys.
You can do this by configuring material providers. These examples use the wrapped provider with ``EncryptedTable``:

* `How to use raw symmetric wrapping keys <./src/dynamodb_encryption_sdk_examples/wrapped_symmetric_encrypted_table.py>`_
* `How to use raw asymmetric wrapping keys <./src/dynamodb_encryption_sdk_examples/wrapped_rsa_encrypted_table.py>`_

For more details on the different type of material providers, see `How to choose a cryptographic materials provider <https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/crypto-materials-providers.html>`_.

Running the examples
====================

In order to run these examples, these things must be configured:

#. Ensure that AWS credentials are available in one of the `automatically discoverable credential locations`_.
#. The ``DDB_ENCRYPTION_CLIENT_TEST_TABLE_NAME`` environment variable must be set to a valid
   DynamoDB table name, in the default region, to which the discoverable credentials have
   read, write, and describe permissions.

.. _automatically discoverable credential locations: http://boto3.readthedocs.io/en/latest/guide/configuration.html
